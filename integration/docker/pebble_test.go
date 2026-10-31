// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

//go:build integration_docker

package docker_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/acme"

	tlsletsencrypt "github.com/altessa-s/go-tlsutils/providers/letsencrypt"
)

const (
	pebbleImage = "ghcr.io/letsencrypt/pebble:2.10.0"
	// pebbleMinica is the CA in the Pebble image that signs the certificate
	// of its ACME and management endpoints (SANs localhost, pebble, 127.0.0.1).
	pebbleMinica = "/test/certs/pebble.minica.pem"
)

// TestPebbleACME obtains a certificate through providers/letsencrypt from a
// Pebble ACME server and verifies a handshake against Pebble's root CA.
// Pebble runs with PEBBLE_VA_ALWAYS_VALID, so no challenge has to reach the
// test process from inside the container.
func TestPebbleACME(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)
	t.Parallel()
	ctx := t.Context()

	ctr, err := testcontainers.Run(ctx, pebbleImage,
		testcontainers.WithExposedPorts("14000/tcp", "15000/tcp"),
		testcontainers.WithEnv(map[string]string{
			"PEBBLE_VA_ALWAYS_VALID": "1",
			"PEBBLE_WFE_NONCEREJECT": "0",
		}),
		testcontainers.WithWaitStrategy(
			wait.ForLog("ACME directory available at"),
			wait.ForListeningPort("14000/tcp"),
			wait.ForListeningPort("15000/tcp"),
		),
	)
	testcontainers.CleanupContainer(t, ctr)
	require.NoError(t, err)

	httpClient := pebbleHTTPClient(t, ctx, ctr)

	acmeEndpoint, err := ctr.PortEndpoint(ctx, "14000/tcp", "https")
	require.NoError(t, err)
	mgmtEndpoint, err := ctr.PortEndpoint(ctx, "15000/tcp", "https")
	require.NoError(t, err)

	provider, err := tlsletsencrypt.New(
		tlsletsencrypt.WithDomains(serverName),
		tlsletsencrypt.WithEmail("admin@example.com"),
		tlsletsencrypt.WithCacheDir(t.TempDir()),
		tlsletsencrypt.WithClient(&acme.Client{
			DirectoryURL: acmeEndpoint + "/dir",
			HTTPClient:   httpClient,
		}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, provider.Close(context.WithoutCancel(ctx))) })

	serverCfg, err := provider.TLSConfig()
	require.NoError(t, err)

	// The first handshake drives the whole ACME order.
	hsCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	root := pebbleRoot(t, ctx, httpClient, mgmtEndpoint)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	state := handshake(t, hsCtx, serverCfg, clientConfig(roots))

	requireVerifiedTo(t, state, root)
	require.GreaterOrEqual(t, len(state.PeerCertificates), 2, "intermediate missing from the served chain")
}

// pebbleHTTPClient returns an HTTP client that trusts Pebble's minica, read
// from the container, and verifies the "pebble" SAN whatever host the mapped
// port is reached on.
func pebbleHTTPClient(tb testing.TB, ctx context.Context, ctr testcontainers.Container) *http.Client {
	tb.Helper()
	rc, err := ctr.CopyFileFromContainer(ctx, pebbleMinica)
	require.NoError(tb, err)
	defer func() { _ = rc.Close() }()
	minica, err := io.ReadAll(rc)
	require.NoError(tb, err)

	pool := x509.NewCertPool()
	require.True(tb, pool.AppendCertsFromPEM(minica), "no certificate in %s", pebbleMinica)

	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    pool,
				ServerName: "pebble",
			},
		},
	}
}

// pebbleRoot fetches the root CA Pebble generated at startup from its
// management interface.
func pebbleRoot(tb testing.TB, ctx context.Context, client *http.Client, mgmtEndpoint string) *x509.Certificate {
	tb.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mgmtEndpoint+"/roots/0", http.NoBody)
	require.NoError(tb, err)
	resp, err := client.Do(req)
	require.NoError(tb, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(tb, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(tb, err)

	return parsePEMCert(tb, body)
}
