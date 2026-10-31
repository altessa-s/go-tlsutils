// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

//go:build integration

package integration_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	tlsutils "github.com/altessa-s/go-tlsutils"
	tlsfile "github.com/altessa-s/go-tlsutils/providers/file"
)

// mtlsServer accepts one connection on a loopback listener, requires and
// verifies a client certificate against clientCAs, and reports the verified
// client leaf (or the handshake error).
func mtlsServer(tb testing.TB, serverCert tls.Certificate, clientCAs *x509.CertPool) (addr string, result <-chan mtlsResult) {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(tb, err)
	tb.Cleanup(func() { _ = ln.Close() })

	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
	ch := make(chan mtlsResult, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ch <- mtlsResult{err: err}
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(handshakeDeadline))
		srv := tls.Server(conn, cfg)
		if err := srv.HandshakeContext(tb.Context()); err != nil {
			ch <- mtlsResult{err: err}
			return
		}
		_, err = srv.Write([]byte("ok"))
		ch <- mtlsResult{peer: srv.ConnectionState().PeerCertificates, err: err}
	}()
	return ln.Addr().String(), ch
}

type mtlsResult struct {
	peer []*x509.Certificate
	err  error
}

// dialAndRead dials addr with cfg and reads the server's two-byte greeting.
// Under TLS 1.3 a rejected client certificate surfaces on this first read.
func dialAndRead(tb testing.TB, addr string, cfg *tls.Config) error {
	tb.Helper()
	d := tls.Dialer{Config: cfg}
	conn, err := d.DialContext(tb.Context(), "tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(handshakeDeadline))
	buf := make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	return err
}

// TestMutualTLS_FileProviderClientCertificate proves that
// tlsutils.ClientTLSConfig, sourcing the client certificate from a file
// provider, authenticates to a server that requires and verifies client
// certificates, and that a client certificate from an untrusted CA is
// rejected.
func TestMutualTLS_FileProviderClientCertificate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		trustClient bool
	}{
		{name: "trusted client certificate", trustClient: true},
		{name: "untrusted client certificate"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			serverPKI := newTestPKI(t)
			clientPKI := serverPKI
			if !tc.trustClient {
				clientPKI = newTestPKI(t)
			}

			clientLeaf := clientPKI.issueLeaf(t, "")
			certPath, keyPath := writeKeyPair(t, t.TempDir(), clientLeaf)
			prov, err := tlsfile.NewWithCertAndKey(certPath, keyPath, "", tlsfile.WithLogger(discardLogger))
			require.NoError(t, err)
			t.Cleanup(func() { _ = prov.Close(t.Context()) })

			addr, result := mtlsServer(t, serverPKI.issueLeaf(t, ""), serverPKI.root.Pool)
			clientCfg := tlsutils.ClientTLSConfig(prov, serverName)
			clientCfg.RootCAs = serverPKI.root.Pool

			clientErr := dialAndRead(t, addr, clientCfg)
			res := <-result
			if !tc.trustClient {
				require.Error(t, res.err, "the server must reject a client certificate from an untrusted CA")
				require.Error(t, clientErr)
				return
			}
			require.NoError(t, clientErr)
			require.NoError(t, res.err)
			require.Len(t, res.peer, 2, "the client presents leaf and intermediate")
			require.True(t, res.peer[0].Equal(clientLeaf.Leaf))
		})
	}
}
