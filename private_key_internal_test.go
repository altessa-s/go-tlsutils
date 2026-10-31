// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlsutils

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/youmark/pkcs8"
)

// TestPrivateKeyScryptValidationBoundary calls only the validator so the normal
// suite covers the 1 GiB boundary without allocating memory or deriving a key.
func TestPrivateKeyScryptValidationBoundary(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int
		want error
	}{
		{"at limit", 1 << 20, nil},
		{"above limit", 1 << 21, ErrInvalidPrivateKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			marshal := func(value any) []byte {
				der, err := asn1.Marshal(value)
				require.NoError(t, err)
				return der
			}
			kdf := marshal(struct {
				Salt    []byte
				N, R, P int
			}{[]byte("salt"), tc.n, 8, 1})
			params := marshal(struct {
				KDF    pkix.AlgorithmIdentifier
				Cipher pkix.AlgorithmIdentifier
			}{
				KDF: pkix.AlgorithmIdentifier{
					Algorithm:  asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11},
					Parameters: asn1.RawValue{FullBytes: kdf},
				},
				Cipher: pkix.AlgorithmIdentifier{
					Algorithm:  asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42},
					Parameters: asn1.RawValue{FullBytes: marshal(make([]byte, 16))},
				},
			})
			envelope := marshal(struct {
				Algorithm pkix.AlgorithmIdentifier
				Data      []byte
			}{
				Algorithm: pkix.AlgorithmIdentifier{
					Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13},
					Parameters: asn1.RawValue{FullBytes: params},
				},
				Data: make([]byte, 16),
			})
			err := validatePrivateKeyKDF(envelope)
			if tc.want == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.want)
			}
		})
	}
}

func TestPrivateKeyCipherValidation(t *testing.T) {
	// Exercise validatePrivateKeyKDF directly: errors here must precede both
	// decryption and the decoder's last-resort panic recovery.
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	for _, cipher := range []pkcs8.Cipher{
		pkcs8.AES128CBC, pkcs8.AES192CBC, pkcs8.AES256CBC,
		pkcs8.AES128GCM, pkcs8.AES192GCM, pkcs8.AES256GCM, pkcs8.TripleDESCBC,
	} {
		t.Run(cipher.OID().String(), func(t *testing.T) {
			der, err := pkcs8.MarshalPrivateKey(key, []byte("password"), &pkcs8.Opts{
				Cipher:  cipher,
				KDFOpts: pkcs8.PBKDF2Opts{SaltSize: 16, IterationCount: 1, HMACHash: crypto.SHA256},
			})
			require.NoError(t, err)
			var original struct {
				Algorithm pkix.AlgorithmIdentifier
				Data      []byte
			}
			_, err = asn1.Unmarshal(der, &original)
			require.NoError(t, err)
			for _, tc := range []struct {
				name           string
				ivLen, dataLen int
				valid          bool
			}{
				{"valid", cipher.IVSize(), len(original.Data), true},
				{"short IV", cipher.IVSize() - 1, len(original.Data), false},
				{"long IV", cipher.IVSize() + 1, len(original.Data), false},
				{"empty ciphertext", cipher.IVSize(), 0, false},
				{"unaligned ciphertext", cipher.IVSize(), len(original.Data) - 1, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					info := original
					var params struct{ KDF, Cipher pkix.AlgorithmIdentifier }
					_, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &params)
					require.NoError(t, err)
					iv, err := asn1.Marshal(make([]byte, tc.ivLen))
					require.NoError(t, err)
					params.Cipher.Parameters = asn1.RawValue{FullBytes: iv}
					info.Algorithm.Parameters.FullBytes, err = asn1.Marshal(params)
					require.NoError(t, err)
					info.Data = make([]byte, tc.dataLen)
					encoded, err := asn1.Marshal(info)
					require.NoError(t, err)
					err = validatePrivateKeyKDF(encoded)
					if tc.valid {
						require.NoError(t, err)
					} else {
						require.ErrorIs(t, err, ErrInvalidPrivateKey)
					}
				})
			}
		})
	}
}
