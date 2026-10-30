// Copyright 2021-2026 ALTESSA SOLUTIONS INC. All rights reserved.
// Use of this source code is governed by license that can be found in
// the LICENSE file.

package tlsutils_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/youmark/pkcs8"

	"github.com/altessa-s/go-tlsutils/internal/testhelpers"

	tlsutils "github.com/altessa-s/go-tlsutils"
)

const pw = "s3cret"

// leaf returns a self-signed certificate PEM for key.
func leaf(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "coverage.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	return testhelpers.GenerateECDSAKey(t, elliptic.P256())
}

func pkcs8PEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func encryptedPKCS8PEM(t *testing.T, key any, password string) []byte {
	t.Helper()
	der, err := pkcs8.MarshalPrivateKey(key, []byte(password), nil)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der})
}

func legacyEncryptedECPEM(t *testing.T, key *ecdsa.PrivateKey, password string) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	//nolint:staticcheck // SA1019: legacy PEM encryption is the format under test
	block, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", der, []byte(password), x509.PEMCipherAES256)
	require.NoError(t, err)
	return pem.EncodeToMemory(block)
}

func writeFile(t *testing.T, name string, data []byte, perm os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(p, data, perm))
	require.NoError(t, os.Chmod(p, perm))
	return p
}

func TestLoadFromBytes_KeyFormats(t *testing.T) {
	t.Parallel()
	ec := ecKey(t)
	rsaKey := testhelpers.GenerateRSAKey(t, 2048)
	ecDER, err := x509.MarshalECPrivateKey(ec)
	require.NoError(t, err)

	tests := []struct {
		name     string
		key      crypto.Signer
		keyPEM   []byte
		password string
	}{
		{"encrypted pkcs8", ec, encryptedPKCS8PEM(t, ec, pw), pw},
		{"pkcs8 with password", ec, pkcs8PEM(t, ec), pw},
		{"pkcs1 rsa with password", rsaKey, pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		}), pw},
		{"sec1 ec with password", ec, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}), pw},
		{"legacy encrypted pem", ec, legacyEncryptedECPEM(t, ec, pw), pw},
		{"plain pkcs8", ec, pkcs8PEM(t, ec), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			certPEM := leaf(t, tc.key)
			cert, err := tlsutils.LoadFromBytes(certPEM, tc.keyPEM, tc.password)
			require.NoError(t, err)
			require.NotNil(t, cert.Leaf)
			require.Equal(t, "coverage.test", cert.Leaf.Subject.CommonName)
			signer, ok := cert.PrivateKey.(crypto.Signer)
			require.True(t, ok)
			require.True(t, signer.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(tc.key.Public()))
		})
	}
}

func TestLoadFromBytes_Failures(t *testing.T) {
	t.Parallel()
	ec := ecKey(t)
	certPEM := leaf(t, ec)

	_, err := tlsutils.LoadFromBytes(certPEM, encryptedPKCS8PEM(t, ec, pw), "wrong")
	require.Error(t, err, "a wrong password must not load")

	_, err = tlsutils.LoadFromBytes(certPEM, encryptedPKCS8PEM(t, ec, pw), "")
	require.Error(t, err, "an encrypted key without a password must not load")

	_, err = tlsutils.LoadFromBytes(certPEM, legacyEncryptedECPEM(t, ec, pw), "wrong")
	require.Error(t, err)

	_, err = tlsutils.LoadFromBytes(certPEM,
		pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("junk")}), pw)
	require.Error(t, err)

	_, err = tlsutils.LoadFromBytes([]byte("not a cert"), pkcs8PEM(t, ec), pw)
	require.Error(t, err)

	_, err = tlsutils.LoadFromBytes(certPEM, []byte("not a key"), pw)
	require.Error(t, err)

	other := ecKey(t)
	_, err = tlsutils.LoadFromBytes(certPEM, pkcs8PEM(t, other), "")
	require.Error(t, err, "a key that does not match the certificate must not load")

	_, err = tlsutils.LoadFromBytes(certPEM, encryptedPKCS8PEM(t, other, pw), pw)
	require.Error(t, err, "a decrypted key that does not match the certificate must not load")

	bundle := bytes.Join([][]byte{certPEM, pkcs8PEM(t, ec)}, nil)
	_, err = tlsutils.LoadFromBytes(bundle, nil, "")
	require.Error(t, err, "a key bundled into the certificate input must not stand in for the key input")
	_, err = tlsutils.LoadFromBytes(bundle, pkcs8PEM(t, other), "")
	require.Error(t, err, "the key input is used even when the certificate input bundles a key")
}

// TestLoadFromFile_KeyOnlyFromKeyFile pins that a world-readable certificate
// file bundling the key cannot bypass the key file's permission check.
func TestLoadFromFile_KeyOnlyFromKeyFile(t *testing.T) {
	t.Parallel()
	ec := ecKey(t)
	bundlePath := writeFile(t, "bundle.pem", bytes.Join([][]byte{leaf(t, ec), pkcs8PEM(t, ec)}, nil), 0o644)
	emptyKey := writeFile(t, "empty.key", nil, 0o600)

	_, err := tlsutils.LoadFromFile(emptyKey, bundlePath, "")
	require.Error(t, err)
}

func TestLoad_KeepsChain(t *testing.T) {
	t.Parallel()
	ca := testhelpers.NewCA(t)
	leafCert := ca.SignLeaf(t, testhelpers.WithCommonName("chain.test"))
	chainPEM := bytes.Join([][]byte{
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Certificate[0]}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}),
	}, nil)

	tests := []struct {
		name     string
		keyPEM   []byte
		password string
	}{
		{"plain pkcs8", pkcs8PEM(t, leafCert.PrivateKey), ""},
		{"encrypted pkcs8", encryptedPKCS8PEM(t, leafCert.PrivateKey, pw), pw},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertChain := func(t *testing.T, cert *tls.Certificate) {
				t.Helper()
				require.Len(t, cert.Certificate, 2)
				require.Equal(t, ca.Cert.Raw, cert.Certificate[1])
				require.Equal(t, "chain.test", cert.Leaf.Subject.CommonName)
			}

			cert, err := tlsutils.LoadFromBytes(chainPEM, tc.keyPEM, tc.password)
			require.NoError(t, err)
			assertChain(t, cert)

			combined := writeFile(t, "combined.pem", bytes.Join([][]byte{tc.keyPEM, chainPEM}, nil), 0o600)
			cert, err = tlsutils.LoadFromConcatenatedFile(combined, tc.password)
			require.NoError(t, err)
			assertChain(t, cert)
		})
	}
}

func TestLoadFromFile(t *testing.T) {
	t.Parallel()
	ec := ecKey(t)
	certPath := writeFile(t, "cert.pem", leaf(t, ec), 0o644)

	keyPath := writeFile(t, "key.pem", pkcs8PEM(t, ec), 0o600)
	cert, err := tlsutils.LoadFromFile(keyPath, certPath, "")
	require.NoError(t, err)
	require.NotNil(t, cert.Leaf)

	encPath := writeFile(t, "enc.pem", encryptedPKCS8PEM(t, ec, pw), 0o600)
	cert, err = tlsutils.LoadFromFile(encPath, certPath, pw)
	require.NoError(t, err)
	require.NotNil(t, cert.Leaf)

	legacyPath := writeFile(t, "legacy.pem", legacyEncryptedECPEM(t, ec, pw), 0o600)
	_, err = tlsutils.LoadFromFile(legacyPath, certPath, pw)
	require.NoError(t, err)

	loosePath := writeFile(t, "loose.pem", pkcs8PEM(t, ec), 0o644)
	_, err = tlsutils.LoadFromFile(loosePath, certPath, "")
	require.ErrorContains(t, err, "insecure permissions")

	_, err = tlsutils.LoadFromFile(filepath.Join(t.TempDir(), "missing.pem"), certPath, "")
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestLoadFromConcatenatedFile(t *testing.T) {
	t.Parallel()
	ec := ecKey(t)
	certPEM := leaf(t, ec)

	plain := writeFile(t, "plain.pem", bytes.Join([][]byte{certPEM, pkcs8PEM(t, ec)}, nil), 0o600)
	cert, err := tlsutils.LoadFromConcatenatedFile(plain, "")
	require.NoError(t, err)
	require.NotNil(t, cert.Leaf)

	enc := writeFile(t, "enc.pem", bytes.Join([][]byte{
		pem.EncodeToMemory(&pem.Block{Type: "COMMENT", Bytes: []byte("x")}),
		certPEM, encryptedPKCS8PEM(t, ec, pw),
	}, nil), 0o600)
	cert, err = tlsutils.LoadFromConcatenatedFile(enc, pw)
	require.NoError(t, err)
	require.Equal(t, "coverage.test", cert.Leaf.Subject.CommonName)

	legacy := writeFile(t, "legacy.pem", bytes.Join([][]byte{legacyEncryptedECPEM(t, ec, pw), certPEM}, nil), 0o600)
	_, err = tlsutils.LoadFromConcatenatedFile(legacy, pw)
	require.NoError(t, err)

	_, err = tlsutils.LoadFromConcatenatedFile(enc, "wrong")
	require.Error(t, err)

	loose := writeFile(t, "loose.pem", bytes.Join([][]byte{certPEM, pkcs8PEM(t, ec)}, nil), 0o640)
	_, err = tlsutils.LoadFromConcatenatedFile(loose, "")
	require.ErrorContains(t, err, "insecure permissions")
}

func TestBuildCAPool_Files(t *testing.T) {
	t.Parallel()
	ec := ecKey(t)
	caPath := writeFile(t, "ca.pem", leaf(t, ec), 0o644)

	pool, err := tlsutils.BuildCAPool(false, caPath)
	require.NoError(t, err)
	require.False(t, pool.Equal(x509.NewCertPool()), "the CA must be added to the pool")

	empty, err := tlsutils.BuildCAPool(false)
	require.NoError(t, err)
	require.True(t, empty.Equal(x509.NewCertPool()))

	_, err = tlsutils.BuildCAPool(false, writeFile(t, "junk.pem", []byte("junk"), 0o644))
	require.ErrorContains(t, err, "failed to parse")

	_, err = tlsutils.BuildCAPool(false, filepath.Join(t.TempDir(), "missing.pem"))
	require.ErrorIs(t, err, os.ErrNotExist)
}
