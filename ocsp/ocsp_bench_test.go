// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package ocsp

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/altessa-s/go-tlsutils/internal/testhelpers"
)

func BenchmarkNewOCSPStapler(b *testing.B) {
	for b.Loop() {
		_ = NewOCSPStapler()
	}
}

// BenchmarkGetOCSPStaple_CacheHit_Compression measures the handshake hot path:
// a valid cached response served with compression enabled.
func BenchmarkGetOCSPStaple_CacheHit_Compression(b *testing.B) {
	s := NewOCSPStapler(WithCompression())
	der := make([]byte, 1200) // typical DER OCSP response size
	for i := range der {
		der[i] = byte(i * 31)
	}
	cert := &tls.Certificate{Certificate: [][]byte{[]byte("leaf-der")}, Leaf: &x509.Certificate{}}
	s.cache[base64.StdEncoding.EncodeToString(cert.Certificate[0])] =
		&ocspCacheEntry{response: der, nextUpdate: time.Now().Add(24 * time.Hour)}
	ctx := b.Context()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := s.GetOCSPStaple(ctx, cert); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGetOCSPStaple_CacheHit_Parallel measures the same cache-hit path
// under concurrent handshakes, since production traffic reads the cache from
// many goroutines at once.
func BenchmarkGetOCSPStaple_CacheHit_Parallel(b *testing.B) {
	s := NewOCSPStapler(WithCompression())
	der := make([]byte, 1200) // typical DER OCSP response size
	for i := range der {
		der[i] = byte(i * 31)
	}
	cert := &tls.Certificate{Certificate: [][]byte{[]byte("leaf-der")}, Leaf: &x509.Certificate{}}
	s.cache[base64.StdEncoding.EncodeToString(cert.Certificate[0])] =
		&ocspCacheEntry{response: der, nextUpdate: time.Now().Add(24 * time.Hour)}
	ctx := b.Context()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := s.GetOCSPStaple(ctx, cert); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkGetOCSPStaple_CacheMiss measures the cold path against a local
// OCSP responder: a full request/response round trip, OCSP parse, and cache
// store. The cache is cleared before each iteration so every call is a miss,
// isolating the fetch cost from certificate minting.
func BenchmarkGetOCSPStaple_CacheMiss(b *testing.B) {
	ca := testhelpers.NewCA(b)
	r := newCountingResponder(b, ca, 3*time.Hour)
	cert := chainWith(b, ca, r.srv.URL)
	s := NewOCSPStapler()
	ctx := b.Context()
	b.ReportAllocs()
	for b.Loop() {
		s.mu.Lock()
		clear(s.cache)
		s.mu.Unlock()
		if _, err := s.GetOCSPStaple(ctx, cert); err != nil {
			b.Fatal(err)
		}
	}
}

// realClientHelloInfo runs a throwaway handshake over an in-memory pipe
// purely to obtain a *tls.ClientHelloInfo carrying a real, non-nil internal
// context: a zero-value one panics against the wrapped GetCertificate's
// context.WithTimeout call, so it cannot stand in for the handshake-hot-path
// benchmark below.
func realClientHelloInfo(b *testing.B, serverCert tls.Certificate) *tls.ClientHelloInfo {
	b.Helper()
	var captured *tls.ClientHelloInfo
	serverCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			captured = hello
			return &serverCert, nil
		},
	}
	cConn, sConn := net.Pipe()
	srv := tls.Server(sConn, serverCfg)
	cli := tls.Client(cConn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // bench helper, no verification needed
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.HandshakeContext(b.Context())
		_ = sConn.Close()
	}()
	if err := cli.HandshakeContext(b.Context()); err != nil {
		b.Fatal(err)
	}
	_ = cConn.Close()
	<-done
	return captured
}

// BenchmarkStapleOCSPToConfig_WrappedGetCertificate measures the
// per-handshake cost of the callback StapleOCSPToConfig installs, with a
// warm cache: certificate selection plus the cache-hit staple clone, without
// a network round trip.
func BenchmarkStapleOCSPToConfig_WrappedGetCertificate(b *testing.B) {
	ca := testhelpers.NewCA(b)
	r := newCountingResponder(b, ca, 3*time.Hour)
	cert := chainWith(b, ca, r.srv.URL)
	s := NewOCSPStapler()
	if _, err := s.GetOCSPStaple(b.Context(), cert); err != nil {
		b.Fatal(err)
	}

	cfg := &tls.Config{Certificates: []tls.Certificate{*cert}}
	if err := StapleOCSPToConfig(cfg, s); err != nil {
		b.Fatal(err)
	}
	hello := realClientHelloInfo(b, *cert)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := cfg.GetCertificate(hello); err != nil {
			b.Fatal(err)
		}
	}
}
