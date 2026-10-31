// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlsutils

import (
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/youmark/pkcs8"
)

const (
	maxPBKDF2Iterations = 10_000_000
	maxScryptMemory     = 1 << 30
	scryptBlockBytes    = 128
	maxScryptN          = 1 << 20
	maxScryptR          = 32
	maxScryptP          = 16
	// Bound CPU work as well as memory when parallelization is requested.
	maxScryptWork = maxScryptMemory / scryptBlockBytes
)

// validatePrivateKeyKDF checks attacker-controlled costs before the PKCS#8
// library runs any KDF, and validates cipher parameters before decryption.
// These structures match the pinned library's ASN.1
// decoding so the checked costs are the ones used for decryption.
func validatePrivateKeyKDF(der []byte) error {
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		Data      []byte
	}
	_, err := asn1.Unmarshal(der, &info)
	if err != nil || !info.Algorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}) {
		return ErrInvalidPrivateKey
	}
	var params struct {
		KDF    pkix.AlgorithmIdentifier
		Cipher pkix.AlgorithmIdentifier
	}
	rest, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &params)
	if err != nil || len(rest) != 0 {
		return ErrInvalidPrivateKey
	}
	if err = validatePrivateKeyCipher(params.Cipher, info.Data); err != nil {
		return err
	}
	switch {
	case params.KDF.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}):
		var kdf struct {
			Salt           []byte
			IterationCount int
			PRF            pkix.AlgorithmIdentifier `asn1:"optional"`
		}
		rest, err = asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdf)
		if err != nil || len(rest) != 0 || kdf.IterationCount < 1 || kdf.IterationCount > maxPBKDF2Iterations {
			return ErrInvalidPrivateKey
		}
	case params.KDF.Algorithm.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}):
		var kdf struct {
			Salt []byte
			N    int
			R    int
			P    int
		}
		rest, err = asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdf)
		if err != nil || len(rest) != 0 {
			return ErrInvalidPrivateKey
		}
		// Check individual bounds first so all following products are safe even
		// on 32-bit platforms. N must be a power of two greater than one.
		if kdf.N < 2 || kdf.N > maxScryptN || kdf.N&(kdf.N-1) != 0 ||
			kdf.R < 1 || kdf.R > maxScryptR || kdf.P < 1 || kdf.P > maxScryptP {
			return ErrInvalidPrivateKey
		}
		if kdf.N*kdf.R > maxScryptMemory/scryptBlockBytes || kdf.N*kdf.R > maxScryptWork/kdf.P {
			return ErrInvalidPrivateKey
		}
	default:
		return ErrInvalidPrivateKey
	}
	return nil
}

// validatePrivateKeyCipher matches the built-in ciphers of the pinned PKCS#8
// dependency. All use CBC internally, including its GCM-labeled AES variants.
func validatePrivateKeyCipher(algorithm pkix.AlgorithmIdentifier, data []byte) error {
	for _, cipher := range []pkcs8.Cipher{
		pkcs8.AES128CBC, pkcs8.AES192CBC, pkcs8.AES256CBC,
		pkcs8.AES128GCM, pkcs8.AES192GCM, pkcs8.AES256GCM, pkcs8.TripleDESCBC,
	} {
		if !algorithm.Algorithm.Equal(cipher.OID()) {
			continue
		}
		var iv []byte
		if _, err := asn1.Unmarshal(algorithm.Parameters.FullBytes, &iv); err != nil {
			return ErrInvalidPrivateKey
		}
		blockSize := cipher.IVSize()
		if len(iv) != blockSize || len(data) == 0 || len(data)%blockSize != 0 {
			return ErrInvalidPrivateKey
		}
		return nil
	}
	return ErrInvalidPrivateKey
}
