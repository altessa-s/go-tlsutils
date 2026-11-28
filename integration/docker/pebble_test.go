// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

//go:build integration_docker

package docker_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
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

	ready := &pebbleReadiness{}
	ctr, err := testcontainers.Run(ctx, pebbleImage,
		testcontainers.WithExposedPorts("14000/tcp", "15000/tcp"),
		testcontainers.WithEnv(map[string]string{
			"PEBBLE_VA_ALWAYS_VALID": "1",
			"PEBBLE_WFE_NONCEREJECT": "0",
		}),
		testcontainers.WithWaitStrategyAndDeadline(2*time.Minute, ready),
	)
	testcontainers.CleanupContainer(t, ctr)
	require.NoError(t, err)

	httpClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: ready.tlsConfig},
	}

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

// pebbleReadiness loads the CA from the image and verifies both HTTPS APIs
// before the test uses them. The ACME client reuses the same TLS configuration.
type pebbleReadiness struct {
	tlsConfig *tls.Config
}

func (p *pebbleReadiness) WaitUntilReady(ctx context.Context, target wait.StrategyTarget) error {
	rc, err := target.CopyFileFromContainer(ctx, pebbleMinica)
	if err != nil {
		return fmt.Errorf("copy Pebble CA: %w", err)
	}

	defer func() { _ = rc.Close() }()

	minica, err := io.ReadAll(rc)
	if err != nil {
		return fmt.Errorf("read Pebble CA: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(minica) {
		return fmt.Errorf("no certificate in %s", pebbleMinica)
	}

	p.tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
		ServerName: "pebble",
	}

	return wait.ForAll(
		wait.ForHTTP("/dir").WithPort("14000/tcp").WithTLS(true, p.tlsConfig.Clone()),
		wait.ForHTTP("/roots/0").WithPort("15000/tcp").WithTLS(true, p.tlsConfig.Clone()),
	).WaitUntilReady(ctx, target)
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
