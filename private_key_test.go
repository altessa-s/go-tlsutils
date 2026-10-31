// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlsutils_test

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/youmark/pkcs8"

	"github.com/altessa-s/go-tlsutils/internal/testhelpers"

	tlsutils "github.com/altessa-s/go-tlsutils"
)

func TestParsePrivateKeyPEM(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ec := ecKey(t)
	rsaKey := testhelpers.GenerateRSAKey(t, 2048)
	ecDER, err := x509.MarshalECPrivateKey(ec)
	require.NoError(t, err)
	for _, key := range []crypto.Signer{ed, ec, rsaKey} {
		for _, encrypted := range []bool{false, true} {
			data := pkcs8PEM(t, key)
			password := ""
			if encrypted {
				password = pw
				data = encryptedPKCS8PEM(t, key, password)
			}
			got, err := tlsutils.ParsePrivateKeyPEM(data, password)
			require.NoError(t, err)
			require.Equal(t, key.Public(), got.Public())
			cert, err := tlsutils.LoadFromBytes(leaf(t, key), data, password)
			require.NoError(t, err)
			require.Equal(t, cert.PrivateKey, got)
			if encrypted {
				got, err = tlsutils.ParsePrivateKeyPEM(data, "wrong")
				require.Nil(t, got)
				require.ErrorIs(t, err, tlsutils.ErrIncorrectPassword)
				require.NotErrorIs(t, err, tlsutils.ErrInvalidPrivateKey)
			}
		}
	}
	for _, tc := range []struct {
		name string
		data []byte
		key  crypto.Signer
	}{
		{"PKCS1", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}), rsaKey},
		{"SEC1", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}), ec},
		{"legacy", legacyEncryptedECPEM(t, ec, pw), ec},
		{"first key", bytes.Join([][]byte{leaf(t, ec), pkcs8PEM(t, ed), pkcs8PEM(t, ec)}, nil), ed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tlsutils.ParsePrivateKeyPEM(tc.data, pw)
			require.NoError(t, err)
			require.Equal(t, tc.key.Public(), got.Public())
		})
	}
}

func TestParsePrivateKeyPEMErrors(t *testing.T) {
	ec := ecKey(t)
	unsupported, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	malformed := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret-key-material")})
	for _, data := range [][]byte{
		nil, {}, []byte("garbage"), leaf(t, ec), pkcs8PEM(t, unsupported),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not a private key")}),
		malformed, append(bytes.Clone(malformed), pkcs8PEM(t, ec)...),
		pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("malformed")}),
	} {
		key, err := tlsutils.ParsePrivateKeyPEM(data, pw)
		require.Nil(t, key)
		require.ErrorIs(t, err, tlsutils.ErrInvalidPrivateKey)
		var typed *tlsutils.PrivateKeyError
		require.ErrorAs(t, err, &typed)
		require.NotContains(t, err.Error(), pw)
		require.NotContains(t, err.Error(), "secret-key-material")
	}
	for _, data := range [][]byte{encryptedPKCS8PEM(t, ec, pw), legacyEncryptedECPEM(t, ec, pw)} {
		key, err := tlsutils.ParsePrivateKeyPEM(data, "")
		require.Nil(t, key)
		require.ErrorIs(t, err, tlsutils.ErrPasswordRequired)
	}
	// A fixed legacy ciphertext makes the wrong-password padding failure deterministic.
	block := &pem.Block{Type: "EC PRIVATE KEY", Headers: map[string]string{
		"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00000000000000000000000000000000",
	}, Bytes: make([]byte, 16)}
	key, err := tlsutils.ParsePrivateKeyPEM(pem.EncodeToMemory(block), "wrong")
	require.Nil(t, key)
	require.ErrorIs(t, err, tlsutils.ErrIncorrectPassword)
}

// truncatedPKCS8 preserves the encryption parameters but makes CBC ciphertext
// non-block-aligned, exercising validation before decryption.
func truncatedPKCS8(t testing.TB, data []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(data)
	var info struct {
		Algorithm asn1.RawValue
		Data      []byte
	}
	_, err := asn1.Unmarshal(block.Bytes, &info)
	require.NoError(t, err)
	info.Data = info.Data[:len(info.Data)-1]
	block.Bytes, err = asn1.Marshal(info)
	require.NoError(t, err)
	return pem.EncodeToMemory(block)
}

func TestParsePrivateKeyPEMMalformedCiphertext(t *testing.T) {
	data := truncatedPKCS8(t, encryptedPKCS8PEM(t, ecKey(t), pw))
	key, err := tlsutils.ParsePrivateKeyPEM(data, pw)
	require.Nil(t, key)
	require.ErrorIs(t, err, tlsutils.ErrInvalidPrivateKey)
}

func FuzzParsePrivateKeyPEM(f *testing.F) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(f, err)
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), "")
	encrypted, err := pkcs8.MarshalPrivateKey(key, []byte(pw), nil)
	require.NoError(f, err)
	encryptedPEM := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encrypted})
	f.Add(encryptedPEM, pw)
	f.Add(encryptedPEM, "wrong")
	f.Add(truncatedPKCS8(f, encryptedPEM), pw)
	f.Add([]byte("garbage"), "password")
	f.Add([]byte{}, "")
	for _, data := range excessiveKDFKeys(f) {
		f.Add(data, pw)
	}
	f.Fuzz(func(t *testing.T, data []byte, password string) {
		if exceedsFuzzKDFBudget(data) {
			t.Skip("KDF exceeds fuzzing budget")
		}
		signer, err := tlsutils.ParsePrivateKeyPEM(data, password)
		if err != nil {
			require.Nil(t, signer)
			var typed *tlsutils.PrivateKeyError
			require.ErrorAs(t, err, &typed)
			matches := 0
			for _, sentinel := range []error{tlsutils.ErrInvalidPrivateKey, tlsutils.ErrIncorrectPassword, tlsutils.ErrPasswordRequired} {
				if errors.Is(err, sentinel) {
					matches++
				}
			}
			require.Equal(t, 1, matches, "every parsing error must wrap exactly one documented sentinel")
			return
		}
		require.NotNil(t, signer)
		der, err := x509.MarshalPKCS8PrivateKey(signer)
		require.NoError(t, err)
		roundTrip, err := tlsutils.ParsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), "")
		require.NoError(t, err)
		require.Equal(t, signer.Public(), roundTrip.Public())
	})
}

// craftedKDFKey builds an encrypted envelope without running the advertised KDF.
func craftedKDFKey(t testing.TB, oid asn1.ObjectIdentifier, params any) []byte {
	t.Helper()
	marshal := func(value any) []byte {
		data, err := asn1.Marshal(value)
		require.NoError(t, err)
		return data
	}
	pbes2 := struct {
		KDF    pkix.AlgorithmIdentifier
		Cipher pkix.AlgorithmIdentifier
	}{
		KDF: pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: asn1.RawValue{FullBytes: marshal(params)}},
		Cipher: pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42},
			Parameters: asn1.RawValue{FullBytes: marshal(make([]byte, 16))},
		},
	}
	info := struct {
		Algorithm pkix.AlgorithmIdentifier
		Data      []byte
	}{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13},
			Parameters: asn1.RawValue{FullBytes: marshal(pbes2)},
		},
		Data: make([]byte, 16),
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: marshal(info)})
}

func excessiveKDFKeys(t testing.TB) map[string][]byte {
	t.Helper()
	pbkdf2OID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	scryptOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}
	keys := make(map[string][]byte)
	for name, iterations := range map[string]int{
		"huge PBKDF2": 1 << 30, "PBKDF2 over limit": 10_000_001, "zero PBKDF2": 0, "negative PBKDF2": -1,
	} {
		keys[name] = craftedKDFKey(t, pbkdf2OID, struct {
			Salt           []byte
			IterationCount int
		}{[]byte("test salt"), iterations})
	}
	for name, costs := range map[string][3]int{
		"huge scrypt N":            {1 << 30, 8, 1},
		"scrypt N above limit":     {1 << 21, 8, 1},
		"scrypt memory over limit": {1 << 20, 16, 1},
		"scrypt work over limit":   {1 << 20, 8, 2},
		"scrypt non power of two":  {3, 8, 1},
		"scrypt N too small":       {1, 8, 1},
		"scrypt negative N":        {-2, 8, 1},
		"scrypt zero r":            {2, 0, 1},
		"scrypt huge r":            {2, 1 << 30, 1},
		"scrypt zero p":            {2, 8, 0},
		"scrypt huge p":            {2, 8, 1 << 30},
	} {
		keys[name] = craftedKDFKey(t, scryptOID, struct {
			Salt    []byte
			N, R, P int
		}{[]byte("test salt"), costs[0], costs[1], costs[2]})
	}
	keys["unknown KDF"] = craftedKDFKey(t, asn1.ObjectIdentifier{1, 2, 3, 4}, struct{ Salt []byte }{[]byte("salt")})
	keys["malformed KDF"] = craftedKDFKey(t, pbkdf2OID, []byte("malformed"))
	return keys
}

func TestParsePrivateKeyPEMKDFLimits(t *testing.T) {
	for name, data := range excessiveKDFKeys(t) {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			signer, err := tlsutils.ParsePrivateKeyPEM(data, pw)
			require.Nil(t, signer)
			require.ErrorIs(t, err, tlsutils.ErrInvalidPrivateKey)
			require.Less(t, time.Since(start), time.Second, "KDF rejection must precede expensive work")
		})
	}
}

func TestParsePrivateKeyPEMScrypt(t *testing.T) {
	key := ecKey(t)
	der, err := pkcs8.MarshalPrivateKey(key, []byte(pw), &pkcs8.Opts{
		Cipher:  pkcs8.AES256CBC,
		KDFOpts: pkcs8.ScryptOpts{SaltSize: 16, CostParameter: 1024, BlockSize: 8, ParallelizationParameter: 1},
	})
	require.NoError(t, err)
	signer, err := tlsutils.ParsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der}), pw)
	require.NoError(t, err)
	require.Equal(t, key.Public(), signer.Public())
}

func TestParsePrivateKeyPEMDecryptedMalformedLegacy(t *testing.T) {
	// Encrypt malformed DER with valid padding: decryption succeeds, parsing fails.
	//nolint:staticcheck // SA1019: legacy PEM encryption is the format under test
	block, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", []byte("invalid DER"), []byte(pw), x509.PEMCipherAES256)
	require.NoError(t, err)
	data := pem.EncodeToMemory(block)
	signer, err := tlsutils.ParsePrivateKeyPEM(data, pw)
	require.Nil(t, signer)
	require.ErrorIs(t, err, tlsutils.ErrIncorrectPassword)
	require.NotErrorIs(t, err, tlsutils.ErrInvalidPrivateKey)
	_, err = tlsutils.LoadFromBytes(leaf(t, ecKey(t)), data, pw)
	require.ErrorIs(t, err, tlsutils.ErrIncorrectPassword)
}

// exceedsFuzzKDFBudget inspects the same first private key as the parser, before
// decryption. Malformed envelopes still exercise the parser's error paths.
func exceedsFuzzKDFBudget(data []byte) bool {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return false
		}
		data = rest
		if !strings.HasSuffix(block.Type, "PRIVATE KEY") {
			continue
		}
		if block.Type != "ENCRYPTED PRIVATE KEY" {
			return false
		}
		var info struct {
			Algorithm pkix.AlgorithmIdentifier
			Data      []byte
		}
		if _, err := asn1.Unmarshal(block.Bytes, &info); err != nil {
			return false
		}
		var params struct {
			KDF    pkix.AlgorithmIdentifier
			Cipher pkix.AlgorithmIdentifier
		}
		if _, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &params); err != nil {
			return false
		}
		switch {
		case params.KDF.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}):
			var kdf struct {
				Salt       []byte
				Iterations int
				PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
			}
			if _, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdf); err != nil {
				return false
			}
			return kdf.Iterations > 100_000
		case params.KDF.Algorithm.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}):
			var kdf struct {
				Salt    []byte
				N, R, P int
			}
			if _, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdf); err != nil {
				return false
			}
			if kdf.N <= 0 || kdf.R <= 0 || kdf.P <= 0 {
				return false
			}
			// Division avoids overflow for arbitrary ASN.1 integers. Bound both
			// memory and work, including the parallelization factor.
			return kdf.N > (1<<14)/kdf.R || kdf.N > (1<<14)/kdf.R/kdf.P
		default:
			return false
		}
	}
}

func TestPrivateKeyFuzzKDFBudget(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	for _, count := range []int{100_000, 100_001} {
		data := craftedKDFKey(t, oid, struct {
			Salt       []byte
			Iterations int
		}{[]byte("salt"), count})
		require.Equal(t, count > 100_000, exceedsFuzzKDFBudget(data))
		require.Equal(t, count > 100_000, exceedsFuzzKDFBudget(append(leaf(t, ecKey(t)), data...)))
	}
	oid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}
	for _, costs := range [][3]int{{2048, 8, 1}, {4096, 8, 1}, {2048, 8, 2}, {1 << 30, 1 << 30, 1 << 30}} {
		data := craftedKDFKey(t, oid, struct {
			Salt    []byte
			N, R, P int
		}{[]byte("salt"), costs[0], costs[1], costs[2]})
		require.Equal(t, costs != [3]int{2048, 8, 1}, exceedsFuzzKDFBudget(data))
	}
	require.False(t, exceedsFuzzKDFBudget([]byte("garbage")))
	require.False(t, exceedsFuzzKDFBudget(pkcs8PEM(t, ecKey(t))))
}

func TestParsePrivateKeyPEMScryptOneGiB(t *testing.T) {
	if os.Getenv("TLSUTILS_EXPENSIVE_TESTS") != "1" {
		t.Skip("set TLSUTILS_EXPENSIVE_TESTS=1 to run the 1 GiB scrypt regression")
	}
	key := ecKey(t)
	der, err := pkcs8.MarshalPrivateKey(key, []byte(pw), &pkcs8.Opts{
		Cipher:  pkcs8.AES256CBC,
		KDFOpts: pkcs8.ScryptOpts{SaltSize: 16, CostParameter: 1 << 20, BlockSize: 8, ParallelizationParameter: 1},
	})
	require.NoError(t, err)
	signer, err := tlsutils.ParsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der}), pw)
	require.NoError(t, err)
	require.Equal(t, key.Public(), signer.Public())
}

func TestParsePrivateKeyPEMLegacyFormats(t *testing.T) {
	rsaKey := testhelpers.GenerateRSAKey(t, 2048)
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edDER, err := x509.MarshalPKCS8PrivateKey(ed)
	require.NoError(t, err)
	for _, format := range []struct {
		name, label string
		der         []byte
		key         crypto.Signer
	}{
		{"PKCS1 RSA", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey), rsaKey},
		{"PKCS8 Ed25519", "PRIVATE KEY", edDER, ed},
	} {
		t.Run(format.name, func(t *testing.T) {
			//nolint:staticcheck // SA1019: legacy encryption is the format under test
			block, err := x509.EncryptPEMBlock(rand.Reader, format.label, format.der, []byte(pw), x509.PEMCipherAES256)
			require.NoError(t, err)
			data := pem.EncodeToMemory(block)
			for _, tc := range []struct {
				name, password string
				want           error
			}{
				{"right", pw, nil}, {"wrong", "wrong", tlsutils.ErrIncorrectPassword}, {"empty", "", tlsutils.ErrPasswordRequired},
			} {
				t.Run(tc.name, func(t *testing.T) {
					signer, err := tlsutils.ParsePrivateKeyPEM(data, tc.password)
					if tc.want != nil {
						require.Nil(t, signer)
						require.ErrorIs(t, err, tc.want)
						return
					}
					require.NoError(t, err)
					require.Equal(t, format.key.Public(), signer.Public())
				})
			}
		})
	}
}

func TestPrivateKeyErrorNilCause(t *testing.T) {
	err := &tlsutils.PrivateKeyError{}
	require.Equal(t, "parse private key", err.Error())
	require.Nil(t, err.Unwrap())
}

func TestParsePrivateKeyPEMWrongIVLength(t *testing.T) {
	block, _ := pem.Decode(encryptedPKCS8PEM(t, ecKey(t), pw))
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		Data      []byte
	}
	_, err := asn1.Unmarshal(block.Bytes, &info)
	require.NoError(t, err)
	var params struct{ KDF, Cipher pkix.AlgorithmIdentifier }
	_, err = asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &params)
	require.NoError(t, err)
	iv, err := asn1.Marshal(make([]byte, 15))
	require.NoError(t, err)
	params.Cipher.Parameters = asn1.RawValue{FullBytes: iv}
	info.Algorithm.Parameters.FullBytes, err = asn1.Marshal(params)
	require.NoError(t, err)
	block.Bytes, err = asn1.Marshal(info)
	require.NoError(t, err)
	signer, err := tlsutils.ParsePrivateKeyPEM(pem.EncodeToMemory(block), pw)
	require.Nil(t, signer)
	require.ErrorIs(t, err, tlsutils.ErrInvalidPrivateKey)
}

func TestParsePrivateKeyPEMTrailingDER(t *testing.T) {
	key := ecKey(t)
	block, _ := pem.Decode(encryptedPKCS8PEM(t, key, pw))
	block.Bytes = append(block.Bytes, []byte("trailing bytes")...)
	// Confirm the public parser preserves the underlying library's behavior.
	parsed, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(pw))
	require.NoError(t, err)
	signer, err := tlsutils.ParsePrivateKeyPEM(pem.EncodeToMemory(block), pw)
	require.NoError(t, err)
	require.Equal(t, parsed, signer)
	require.Equal(t, key.Public(), signer.Public())
}
