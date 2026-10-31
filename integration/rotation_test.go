// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

//go:build integration

package integration_test

import (
	"crypto/tls"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-tlsutils/ocsp"

	tlsfile "github.com/altessa-s/go-tlsutils/providers/file"
)

// TestFileProvider_RotationUnderLoad proves that a watched file provider
// rotates its certificate without dropping connections: handshakes run
// continuously while the key and certificate files are rewritten, none of
// them fails, and once the reload is signaled every new handshake presents
// the new leaf.
func TestFileProvider_RotationUnderLoad(t *testing.T) {
	t.Parallel()
	const workers = 4

	pki := newTestPKI(t)
	resp := newResponder(t, pki.inter, 0)
	oldLeaf := pki.issueLeaf(t, resp.URL())
	newLeaf := pki.issueLeaf(t, resp.URL())

	dir := t.TempDir()
	certPath, keyPath := writeKeyPair(t, dir, oldLeaf)
	notify := make(chan struct{}, 1)
	prov, err := tlsfile.NewWithCertAndKey(certPath, keyPath, "",
		tlsfile.WithEnableWatcher(),
		tlsfile.WithReloadNotifyChan(notify),
		tlsfile.WithOcspStapler(newStapler(ocsp.FailureModeSoft)),
		tlsfile.WithLogger(discardLogger),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = prov.Close(t.Context()) })
	waitNotify(t, notify, "the initial load signals the channel")

	// Every handshake asks the provider for its current config, as a server
	// following rotations would.
	serverCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return prov.TLSConfig()
		},
	}

	var (
		total, oldSeen, newSeen, unknown atomic.Int64
		failMu                           sync.Mutex
		failures                         []error
	)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				state, err := handshake(t, serverCfg, pki.clientConfig())
				total.Add(1)
				if err != nil {
					failMu.Lock()
					failures = append(failures, err)
					failMu.Unlock()
					continue
				}
				switch leaf := state.PeerCertificates[0]; {
				case leaf.Equal(oldLeaf.Leaf):
					oldSeen.Add(1)
				case leaf.Equal(newLeaf.Leaf):
					newSeen.Add(1)
				default:
					unknown.Add(1)
				}
			}
		})
	}
	stopLoad := sync.OnceFunc(func() {
		close(stop)
		wg.Wait()
	})
	t.Cleanup(stopLoad)

	require.Eventually(t, func() bool { return oldSeen.Load() >= 20 }, waitFor, tick, "load must be running before rotation")

	writeKeyPair(t, dir, newLeaf)
	waitNotify(t, notify, "the watcher must reload the rewritten files")

	// The config is swapped before the notification, so a fresh handshake
	// presents the new leaf right away.
	state, err := handshake(t, serverCfg, pki.clientConfig())
	require.NoError(t, err)
	require.True(t, state.PeerCertificates[0].Equal(newLeaf.Leaf), "a handshake after the reload must see the new leaf")
	requireGoodStaple(t, state, pki.inter.Cert)

	require.Eventually(t, func() bool { return newSeen.Load() >= 20 }, waitFor, tick, "load must continue on the new leaf")
	stopLoad()

	failMu.Lock()
	defer failMu.Unlock()
	require.Empty(t, failures, "no handshake may fail during rotation (of %d)", total.Load())
	require.Zero(t, unknown.Load())
}
