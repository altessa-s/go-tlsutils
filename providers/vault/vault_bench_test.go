// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlsvault_test

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"github.com/altessa-s/go-tlsutils/internal/testhelpers"

	tlsvault "github.com/altessa-s/go-tlsutils/providers/vault"
)

// BenchmarkGetCertificate_WarmCache exercises the handshake hot path once the
// certify cache has been warmed by a prior issuance, so each iteration hits
// the cache instead of round-tripping to Vault's PKI backend.
func BenchmarkGetCertificate_WarmCache(b *testing.B) {
	f := &fakePKI{ca: testhelpers.NewCA(b)}
	srv := httptest.NewServer(f)
	b.Cleanup(srv.Close)

	v, err := tlsvault.New(
		tlsvault.WithEndpoint(srv.URL),
		tlsvault.WithStaticToken("s.static"),
		tlsvault.WithRole("web"),
		tlsvault.WithCommonName("svc.example.com"),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = v.Close(b.Context()) })

	hello := &tls.ClientHelloInfo{ServerName: "svc.example.com"}
	if _, err := v.GetCertificate(hello); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for b.Loop() {
		_, _ = v.GetCertificate(hello)
	}
}

func BenchmarkRSAGenerator_Generate(b *testing.B) {
	gen := tlsvault.NewRSAGenerator()
	for b.Loop() {
		_, _ = gen.Generate()
	}
}

func BenchmarkNewLogger(b *testing.B) {
	for b.Loop() {
		_ = tlsvault.NewLogger(nil)
	}
}
