// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

//go:build integration

package integration_test

import (
	"crypto/tls"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-tlsutils/ocsp"
	tlsfile "github.com/altessa-s/go-tlsutils/providers/file"
)

// newFileProvider writes cert to a fresh directory and serves it through a
// file provider stapled by stapler. The provider is closed on cleanup.
func newFileProvider(tb testing.TB, cert tls.Certificate, stapler *ocsp.Stapler, opts ...tlsfile.Option) *tlsfile.File {
	tb.Helper()
	certPath, keyPath := writeKeyPair(tb, tb.TempDir(), cert)
	opts = append([]tlsfile.Option{tlsfile.WithLogger(discardLogger), tlsfile.WithOcspStapler(stapler)}, opts...)
	prov, err := tlsfile.NewWithCertAndKey(certPath, keyPath, "", opts...)
	require.NoError(tb, err)
	tb.Cleanup(func() { _ = prov.Close(tb.Context()) })
	return prov
}

func newStapler(mode ocsp.FailureMode) *ocsp.Stapler {
	return ocsp.NewOCSPStapler(ocsp.WithFailureMode(mode), ocsp.WithLogger(discardLogger))
}

// TestFileProvider_StapledHandshake proves that a file provider serving a
// leaf+intermediate chain, wrapped by a Soft-mode stapler, completes a
// handshake that the client verifies against the root pool, and that the
// staple it receives is a Good response for the served leaf.
func TestFileProvider_StapledHandshake(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t)
	resp := newResponder(t, pki.inter, 0)
	leaf := pki.issueLeaf(t, resp.URL())

	prov := newFileProvider(t, leaf, newStapler(ocsp.FailureModeSoft))
	serverCfg, err := prov.TLSConfig()
	require.NoError(t, err)

	state, err := handshake(t, serverCfg, pki.clientConfig())
	require.NoError(t, err)
	require.NotEmpty(t, state.VerifiedChains, "the client must verify the chain against the root pool")
	require.Len(t, state.PeerCertificates, 2, "the server sends leaf and intermediate")
	require.True(t, state.PeerCertificates[0].Equal(leaf.Leaf))
	require.True(t, state.PeerCertificates[1].Equal(pki.inter.Cert))
	requireGoodStaple(t, state, pki.inter.Cert)
	require.Equal(t, int32(1), resp.requests.Load())
}

// TestFailureModes proves the stapler's failure mode end to end: in Hard mode
// a responder error or a revoked status aborts the handshake, while in Soft
// mode an unreachable responder still lets the handshake succeed, without a
// staple.
func TestFailureModes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mode      ocsp.FailureMode
		respMode  int32
		down      bool
		wantErr   bool
		wantFetch bool
	}{
		{name: "hard responder 500", mode: ocsp.FailureModeHard, respMode: respondError, wantErr: true, wantFetch: true},
		{name: "hard revoked", mode: ocsp.FailureModeHard, respMode: respondRevoked, wantErr: true, wantFetch: true},
		{name: "soft responder down", mode: ocsp.FailureModeSoft, down: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pki := newTestPKI(t)
			resp := newResponder(t, pki.inter, 0)
			resp.mode.Store(tc.respMode)
			url := resp.URL()
			if tc.down {
				url = deadURL(t)
			}

			prov := newFileProvider(t, pki.issueLeaf(t, url), newStapler(tc.mode))
			serverCfg, err := prov.TLSConfig()
			require.NoError(t, err)

			state, err := handshake(t, serverCfg, pki.clientConfig())
			if tc.wantErr {
				require.Error(t, err, "hard mode must reject the handshake")
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, state.VerifiedChains)
				require.Empty(t, state.OCSPResponse, "soft mode serves the certificate without a staple")
			}
			if tc.wantFetch {
				require.Positive(t, resp.requests.Load(), "the responder must have been consulted")
			}
		})
	}
}

// TestOCSP_SingleflightAcrossHandshakes proves that concurrent handshakes on
// a cold cache share one responder fetch: every handshake gets a Good staple
// while the responder sees exactly one request.
func TestOCSP_SingleflightAcrossHandshakes(t *testing.T) {
	t.Parallel()
	const handshakes = 16

	pki := newTestPKI(t)
	// The delay keeps the first fetch in flight while the others join it.
	resp := newResponder(t, pki.inter, 200*time.Millisecond)
	prov := newFileProvider(t, pki.issueLeaf(t, resp.URL()), newStapler(ocsp.FailureModeHard))
	serverCfg, err := prov.TLSConfig()
	require.NoError(t, err)

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		states []tls.ConnectionState
		errs   []error
	)
	start := make(chan struct{})
	for range handshakes {
		wg.Go(func() {
			<-start
			state, err := handshake(t, serverCfg, pki.clientConfig())
			mu.Lock()
			defer mu.Unlock()
			states = append(states, state)
			errs = append(errs, err)
		})
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err)
		requireGoodStaple(t, states[i], pki.inter.Cert)
	}
	require.Equal(t, int32(1), resp.requests.Load(), "concurrent cold-cache handshakes must share one fetch")
}
