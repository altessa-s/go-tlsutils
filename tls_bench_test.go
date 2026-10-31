// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlsutils_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/youmark/pkcs8"

	tlsutils "github.com/altessa-s/go-tlsutils"
)

type noopClientCert struct{}

func (noopClientCert) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return &tls.Certificate{}, nil
}

func BenchmarkClientTLSConfig(b *testing.B) {
	src := noopClientCert{}
	for b.Loop() {
		_ = tlsutils.ClientTLSConfig(src, "peer.internal")
	}
}

// BenchmarkDefaultTLSConfig measures building the default server TLS config,
// which clones the pinned cipher list on every call so callers can mutate
// their own copy without aliasing the package-level slice.
func BenchmarkDefaultTLSConfig(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = tlsutils.DefaultTLSConfig()
	}
}

const benchKeyPassword = "s3cret-bench" //nolint:gosec // G101: benchmark fixture, not a real credential

// benchChainAndEncryptedKey builds a leaf+intermediate PEM chain and the
// leaf's key as an encrypted PKCS#8 PEM block, mirroring the startup/reload
// shape LoadFromBytes sees in production: a multi-certificate chain and a
// password-protected key.
func benchChainAndEncryptedKey(tb testing.TB) (certPEM, keyPEM []byte) {
	tb.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "bench-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		tb.Fatalf("create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		tb.Fatalf("parse CA certificate: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "bench-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, leafKey.Public(), caKey)
	if err != nil {
		tb.Fatalf("create leaf certificate: %v", err)
	}

	certPEM = bytes.Join([][]byte{
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
	}, nil)

	der, err := pkcs8.MarshalPrivateKey(leafKey, []byte(benchKeyPassword), nil)
	if err != nil {
		tb.Fatalf("marshal encrypted key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der})
	return certPEM, keyPEM
}

// BenchmarkLoadFromBytes_ChainEncryptedKey measures the startup/reload path:
// parsing a leaf+intermediate chain and decrypting an encrypted PKCS#8 key,
// the shape providers reload on every certificate rotation.
func BenchmarkLoadFromBytes_ChainEncryptedKey(b *testing.B) {
	certPEM, keyPEM := benchChainAndEncryptedKey(b)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := tlsutils.LoadFromBytes(certPEM, keyPEM, benchKeyPassword); err != nil {
			b.Fatal(err)
		}
	}
}
