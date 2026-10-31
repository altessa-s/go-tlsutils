// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

//go:build integration_docker

package docker_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// serverName is the DNS name every scenario issues and verifies.
const serverName = "app.example.com"

// errNotTLS reports a connection that is not a [*tls.Conn].
var errNotTLS = errors.New("connection is not a *tls.Conn")

// tryHandshake serves one TLS connection with server on a loopback listener,
// dials it with client and returns the client's view of the connection. It
// fails when either side of the handshake fails.
func tryHandshake(ctx context.Context, server, client *tls.Config) (tls.ConnectionState, error) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", server)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer func() { _ = ln.Close() }()

	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer func() { _ = conn.Close() }()
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			srvErr <- errNotTLS
			return
		}
		srvErr <- tlsConn.HandshakeContext(ctx)
	}()

	dialer := tls.Dialer{Config: client}
	conn, err := dialer.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer func() { _ = conn.Close() }()

	if err := <-srvErr; err != nil {
		return tls.ConnectionState{}, err
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return tls.ConnectionState{}, errNotTLS
	}
	return tlsConn.ConnectionState(), nil
}

// handshake is [tryHandshake] that fails the test on error.
func handshake(tb testing.TB, ctx context.Context, server, client *tls.Config) tls.ConnectionState {
	tb.Helper()
	state, err := tryHandshake(ctx, server, client)
	require.NoError(tb, err, "TLS handshake")
	return state
}

// clientConfig returns a client config that trusts only roots and verifies
// [serverName].
func clientConfig(roots *x509.CertPool) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
		ServerName: serverName,
	}
}

// parsePEMCert decodes the first certificate in pemData.
func parsePEMCert(tb testing.TB, pemData []byte) *x509.Certificate {
	tb.Helper()
	block, _ := pem.Decode(pemData)
	require.NotNil(tb, block, "no PEM block")
	require.Equal(tb, "CERTIFICATE", block.Type)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(tb, err)
	return cert
}

// requireVerifiedTo asserts that the handshake verified a chain ending at root
// and that the served leaf names [serverName].
func requireVerifiedTo(tb testing.TB, state tls.ConnectionState, root *x509.Certificate) {
	tb.Helper()
	require.NotEmpty(tb, state.PeerCertificates, "server sent no certificates")
	require.NoError(tb, state.PeerCertificates[0].VerifyHostname(serverName))
	require.NotEmpty(tb, state.VerifiedChains, "no verified chain")
	chain := state.VerifiedChains[0]
	require.True(tb, chain[len(chain)-1].Equal(root), "verified chain does not end at the expected root")
}

// testCA is a certificate authority for the S3 scenario: a root, an
// intermediate signed by it, and leaves signed by the intermediate.
type testCA struct {
	root     *x509.Certificate
	inter    *x509.Certificate
	interKey *ecdsa.PrivateKey
	serial   int64
}

func newTestCA(tb testing.TB) *testCA {
	tb.Helper()
	rootKey := newKey(tb)
	root := createCert(tb, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "go-tlsutils integration root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}, nil, rootKey, rootKey)

	interKey := newKey(tb)
	inter := createCert(tb, &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "go-tlsutils integration intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}, root, interKey, rootKey)

	return &testCA{root: root, inter: inter, interKey: interKey, serial: 2}
}

// issueLeaf returns a leaf for [serverName] signed by the intermediate, the
// PEM of the leaf followed by the intermediate, and the PKCS#8 key PEM.
func (ca *testCA) issueLeaf(tb testing.TB) (leaf *x509.Certificate, chainPEM, keyPEM []byte) {
	tb.Helper()
	ca.serial++
	key := newKey(tb)
	leaf = createCert(tb, &x509.Certificate{
		SerialNumber: big.NewInt(ca.serial),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca.inter, key, ca.interKey)

	chainPEM = append(pemEncode("CERTIFICATE", leaf.Raw), pemEncode("CERTIFICATE", ca.inter.Raw)...)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(tb, err)
	return leaf, chainPEM, pemEncode("PRIVATE KEY", der)
}

func newKey(tb testing.TB) *ecdsa.PrivateKey {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(tb, err)
	return key
}

// createCert signs tmpl with signerKey; a nil parent self-signs.
func createCert(tb testing.TB, tmpl, parent *x509.Certificate, key, signerKey *ecdsa.PrivateKey) *x509.Certificate {
	tb.Helper()
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), signerKey)
	require.NoError(tb, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(tb, err)
	return cert
}

func pemEncode(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}
