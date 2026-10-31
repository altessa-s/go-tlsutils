// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlsutils_test

import (
	"crypto/tls"
	"testing"

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
