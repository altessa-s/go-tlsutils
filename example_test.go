// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlsutils_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"

	tlsutils "github.com/altessa-s/go-tlsutils"
)

func ExampleParsePrivateKeyPEM() {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	signer, err := tlsutils.ParsePrivateKeyPEM(data, "")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%T\n", signer)
	// Output: ed25519.PrivateKey
}
