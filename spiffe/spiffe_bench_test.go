// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package spiffe_test

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/altessa-s/go-tlsutils/internal/testhelpers"
	"github.com/altessa-s/go-tlsutils/spiffe"
)

func BenchmarkMTLSServerConfig(b *testing.B) {
	p, err := spiffe.NewProvider(&fakeSource{}, anyAuthorizer())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = p.MTLSServerConfig()
	}
}

// benchSVID mints a CA-signed SVID for idStr. It mirrors integration_test.go's
// makeSVID but takes testing.TB so a benchmark can call it.
func benchSVID(tb testing.TB, ca *testhelpers.CA, idStr string) *x509svid.SVID {
	tb.Helper()
	id := spiffeid.RequireFromString(idStr)
	uri, err := url.Parse(id.String())
	if err != nil {
		tb.Fatalf("parse SPIFFE ID: %v", err)
	}
	cert := ca.SignLeaf(tb,
		testhelpers.WithURIs(uri),
		testhelpers.WithExtKeyUsage(x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth),
	)
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		tb.Fatal("leaf private key is not a crypto.Signer")
	}
	return &x509svid.SVID{ID: id, Certificates: []*x509.Certificate{cert.Leaf}, PrivateKey: signer}
}

// BenchmarkMTLSServerConfig_GetCertificate measures the per-handshake cost of
// the GetCertificate callback go-spiffe installs on the server config — the
// code path a real TLS handshake runs on every connection — as opposed to
// BenchmarkMTLSServerConfig, which measures building the *tls.Config once at
// startup.
func BenchmarkMTLSServerConfig_GetCertificate(b *testing.B) {
	td := spiffeid.RequireTrustDomainFromString("bench.example.org")
	ca := testhelpers.NewCA(b)
	bundle := x509bundle.FromX509Authorities(td, []*x509.Certificate{ca.Cert})
	source := &staticSource{
		svid:   benchSVID(b, ca, "spiffe://bench.example.org/server"),
		bundle: bundle,
	}

	p, err := spiffe.NewProvider(source, anyAuthorizer())
	if err != nil {
		b.Fatal(err)
	}
	cfg := p.MTLSServerConfig()
	hello := &tls.ClientHelloInfo{}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := cfg.GetCertificate(hello); err != nil {
			b.Fatal(err)
		}
	}
}
