// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlsvault

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

// DefaultRSAKeyBits is the default RSA key size in bits.
const DefaultRSAKeyBits = 2048

// RSAGenerator generates RSA private keys for certificates.
// Every call generates a new key, so each issued or renewed certificate gets
// its own key and a compromised key does not survive renewal.
type RSAGenerator struct {
	bits int
}

// NewRSAGenerator creates a new RSA key generator with default key size.
//
// Example:
//
//	gen := NewRSAGenerator()
//	key, err := gen.Generate()
func NewRSAGenerator() *RSAGenerator {
	return &RSAGenerator{
		bits: DefaultRSAKeyBits,
	}
}

// Generate creates a new RSA private key.
func (s *RSAGenerator) Generate() (crypto.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, s.bits)
}
