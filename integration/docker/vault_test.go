// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

//go:build integration_docker

package docker_test

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcvault "github.com/testcontainers/testcontainers-go/modules/vault"

	tlsvault "github.com/altessa-s/go-tlsutils/providers/vault"
)

const (
	vaultImage = "hashicorp/vault:1.20.0"
	vaultToken = "integration-root-token"
	vaultRole  = "integration"
)

// TestVaultPKI issues a certificate through providers/vault from a Vault dev
// server's PKI engine and verifies a handshake against the Vault root CA.
func TestVaultPKI(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)
	t.Parallel()
	ctx := t.Context()

	ctr, err := tcvault.Run(ctx, vaultImage, tcvault.WithToken(vaultToken))
	testcontainers.CleanupContainer(t, ctr)
	require.NoError(t, err)

	addr, err := ctr.HttpHostAddress(ctx)
	require.NoError(t, err)

	root := setupVaultPKI(t, ctx, addr)

	provider, err := tlsvault.New(
		tlsvault.WithEndpoint(addr),
		tlsvault.WithStaticToken(vaultToken),
		tlsvault.WithRole(vaultRole),
		tlsvault.WithCommonName(serverName),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, provider.Close(context.WithoutCancel(ctx))) })

	serverCfg, err := provider.TLSConfig()
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	hsCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	state := handshake(t, hsCtx, serverCfg, clientConfig(roots))

	requireVerifiedTo(t, state, root)
	require.GreaterOrEqual(t, len(state.PeerCertificates), 2, "issuing CA missing from the served chain")
	require.True(t, state.PeerCertificates[1].Equal(root), "served chain does not carry the Vault issuing CA")
}

// setupVaultPKI mounts the PKI engine, generates a root CA and creates
// [vaultRole] allowing subdomains of example.com. It returns the root.
func setupVaultPKI(tb testing.TB, ctx context.Context, addr string) *x509.Certificate {
	tb.Helper()

	cfg := vaultapi.DefaultConfig()
	require.NoError(tb, cfg.Error)
	cfg.Address = addr
	cli, err := vaultapi.NewClient(cfg)
	require.NoError(tb, err)
	cli.SetToken(vaultToken)

	require.NoError(tb, cli.Sys().MountWithContext(ctx, "pki", &vaultapi.MountInput{
		Type:   "pki",
		Config: vaultapi.MountConfigInput{MaxLeaseTTL: "87600h"},
	}))

	secret, err := cli.Logical().WriteWithContext(ctx, "pki/root/generate/internal", map[string]any{
		"common_name": "go-tlsutils integration Vault root",
		"key_type":    "ec",
		"ttl":         "87600h",
	})
	require.NoError(tb, err)
	require.NotNil(tb, secret)
	rootPEM, ok := secret.Data["certificate"].(string)
	require.True(tb, ok, "root generation returned no certificate")

	_, err = cli.Logical().WriteWithContext(ctx, "pki/roles/"+vaultRole, map[string]any{
		"allowed_domains":  "example.com",
		"allow_subdomains": true,
		"key_type":         "any",
		"max_ttl":          "24h",
	})
	require.NoError(tb, err)

	return parsePEMCert(tb, []byte(rootPEM))
}
