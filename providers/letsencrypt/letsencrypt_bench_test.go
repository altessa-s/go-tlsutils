// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlsletsencrypt_test

import (
	"context"
	"crypto/tls"
	"log/slog"
	"testing"

	"golang.org/x/crypto/acme"

	tlsletsencrypt "github.com/altessa-s/go-tlsutils/providers/letsencrypt"
)

// newBenchProvider builds a provider that never contacts a real ACME
// directory, suitable for benchmarking the parts of the handshake path that
// do not depend on network round-trips.
func newBenchProvider(tb testing.TB) *tlsletsencrypt.LetsEncrypt {
	tb.Helper()
	le, err := tlsletsencrypt.New(
		tlsletsencrypt.WithDomains("example.com"),
		tlsletsencrypt.WithEmail("admin@example.com"),
		tlsletsencrypt.WithCacheDir(tb.TempDir()),
		tlsletsencrypt.WithClient(&acme.Client{DirectoryURL: "http://127.0.0.1:1/directory"}),
		tlsletsencrypt.WithLogger(slog.New(slog.DiscardHandler)),
	)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = le.Close(context.Background()) })
	return le
}

// BenchmarkTLSConfig measures building the per-listener TLS config, which
// crypto/tls consults for cipher/version defaults on every handshake.
func BenchmarkTLSConfig(b *testing.B) {
	le := newBenchProvider(b)

	b.ReportAllocs()
	for b.Loop() {
		_, _ = le.TLSConfig()
	}
}

// BenchmarkGetCertificate_RejectedHost measures the host-policy check that
// GetCertificate runs on every handshake before any ACME traffic, using a
// host outside the configured domain list so no network call is made.
func BenchmarkGetCertificate_RejectedHost(b *testing.B) {
	le := newBenchProvider(b)
	hello := &tls.ClientHelloInfo{ServerName: "not-configured.example.org"}

	b.ReportAllocs()
	for b.Loop() {
		_, _ = le.GetCertificate(hello)
	}
}
