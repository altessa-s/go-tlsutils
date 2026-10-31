// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

//go:build integration

package integration_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	xocsp "golang.org/x/crypto/ocsp"

	"github.com/altessa-s/go-tlsutils/internal/testhelpers"
)

const (
	// serverName is the DNS SAN of every leaf minted by [testPKI.issueLeaf].
	serverName = "localhost"
	// handshakeDeadline bounds every pipe handshake so a stuck peer fails the
	// test instead of hanging it.
	handshakeDeadline = 10 * time.Second
	// waitFor and tick drive require.Eventually.
	waitFor = 5 * time.Second
	tick    = 10 * time.Millisecond
)

var discardLogger = slog.New(slog.DiscardHandler)

// testPKI is a two-level hierarchy: a root trusted by clients and an
// intermediate that issues leaves and signs OCSP responses.
type testPKI struct {
	root  *testhelpers.CA
	inter *testhelpers.CA
}

func newTestPKI(tb testing.TB) *testPKI {
	tb.Helper()
	root := testhelpers.NewCA(tb, testhelpers.WithCommonName("integration-root"))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(tb, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "integration-intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.Cert, key.Public(), root.Key)
	require.NoError(tb, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(tb, err)

	return &testPKI{root: root, inter: &testhelpers.CA{Cert: cert, Key: key, Pool: root.Pool}}
}

// issueLeaf mints a server- and client-auth leaf for [serverName] signed by
// the intermediate, with the intermediate appended to the chain. A non-empty
// ocspURL is embedded as the leaf's OCSP responder.
func (p *testPKI) issueLeaf(tb testing.TB, ocspURL string) tls.Certificate {
	tb.Helper()
	opts := []testhelpers.CertOption{
		testhelpers.WithCommonName(serverName),
		testhelpers.WithDNSNames(serverName),
		testhelpers.WithIPAddresses(net.IPv4(127, 0, 0, 1)),
		testhelpers.WithExtKeyUsage(x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth),
	}
	if ocspURL != "" {
		opts = append(opts, testhelpers.WithOCSPServers(ocspURL))
	}
	cert := p.inter.SignLeaf(tb, opts...)
	cert.Certificate = append(cert.Certificate, p.inter.Cert.Raw)
	return cert
}

// clientConfig verifies the server chain against the root pool.
func (p *testPKI) clientConfig() *tls.Config {
	return &tls.Config{RootCAs: p.root.Pool, ServerName: serverName, MinVersion: tls.VersionTLS12}
}

// chainPEM encodes every certificate of cert's chain, leaf first.
func chainPEM(cert tls.Certificate) []byte {
	var out []byte
	for _, der := range cert.Certificate {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out
}

// keyPEM encodes cert's private key as PKCS#8.
func keyPEM(tb testing.TB, cert tls.Certificate) []byte {
	tb.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	require.NoError(tb, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// writeKeyPair writes cert's chain (0644) and key (0600) into dir and returns
// their paths. Existing files are rewritten in place, keeping their inode so
// a file watcher keeps tracking them; the key goes first so a reader never
// pairs the new certificate with the old key.
func writeKeyPair(tb testing.TB, dir string, cert tls.Certificate) (certPath, keyPath string) {
	tb.Helper()
	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")
	require.NoError(tb, os.WriteFile(keyPath, keyPEM(tb, cert), 0o600))
	require.NoError(tb, os.WriteFile(certPath, chainPEM(cert), 0o644)) //nolint:gosec // certificates are public
	return certPath, keyPath
}

// responder modes.
const (
	respondGood int32 = iota
	respondRevoked
	respondError
)

// responder is an OCSP responder that signs answers with the issuing CA and
// counts the requests it receives.
type responder struct {
	issuer   *testhelpers.CA
	mode     atomic.Int32
	delay    time.Duration
	requests atomic.Int32
	srv      *httptest.Server
}

// newResponder starts a responder for leaves issued by issuer. A positive
// delay holds every answer back, widening the window in which concurrent
// fetches overlap.
func newResponder(tb testing.TB, issuer *testhelpers.CA, delay time.Duration) *responder {
	tb.Helper()
	r := &responder{issuer: issuer, delay: delay}
	r.srv = httptest.NewServer(r)
	tb.Cleanup(r.srv.Close)
	return r
}

func (r *responder) URL() string { return r.srv.URL }

func (r *responder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.requests.Add(1)
	if r.delay > 0 {
		timer := time.NewTimer(r.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-req.Context().Done():
			return
		}
	}

	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<16))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ocspReq, err := xocsp.ParseRequest(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	now := time.Now()
	tmpl := xocsp.Response{
		Status:       xocsp.Good,
		SerialNumber: ocspReq.SerialNumber,
		ThisUpdate:   now.Add(-time.Minute),
		NextUpdate:   now.Add(time.Hour),
	}
	switch r.mode.Load() {
	case respondError:
		http.Error(w, "responder failure", http.StatusInternalServerError)
		return
	case respondRevoked:
		tmpl.Status = xocsp.Revoked
		tmpl.RevokedAt = now.Add(-time.Minute)
		tmpl.RevocationReason = xocsp.KeyCompromise
	}

	der, err := xocsp.CreateResponse(r.issuer.Cert, r.issuer.Cert, tmpl, r.issuer.Key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	_, _ = w.Write(der)
}

// deadURL returns the URL of a loopback server that has already shut down, so
// connections to it are refused.
func deadURL(tb testing.TB) string {
	tb.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	return url
}

// handshake runs a full TLS handshake over net.Pipe and returns the client's
// view of the connection. The error joins both sides' failures. It does not
// call require, so it is safe from worker goroutines.
func handshake(tb testing.TB, serverCfg, clientCfg *tls.Config) (tls.ConnectionState, error) {
	tb.Helper()
	cConn, sConn := net.Pipe()
	defer func() { _ = cConn.Close() }()
	defer func() { _ = sConn.Close() }()
	deadline := time.Now().Add(handshakeDeadline)
	_ = cConn.SetDeadline(deadline)
	_ = sConn.SetDeadline(deadline)

	ctx := tb.Context()
	srv := tls.Server(sConn, serverCfg)
	done := make(chan error, 1)
	go func() {
		err := srv.HandshakeContext(ctx)
		if err != nil {
			_ = sConn.Close()
		}
		done <- err
	}()

	cli := tls.Client(cConn, clientCfg)
	cErr := cli.HandshakeContext(ctx)
	if cErr != nil {
		_ = cConn.Close()
	}
	sErr := <-done
	if err := errors.Join(cErr, sErr); err != nil {
		return tls.ConnectionState{}, err
	}
	return cli.ConnectionState(), nil
}

// requireGoodStaple asserts that state carries an OCSP staple for its leaf,
// signed by issuer, reporting Good.
func requireGoodStaple(tb testing.TB, state tls.ConnectionState, issuer *x509.Certificate) {
	tb.Helper()
	require.NotEmpty(tb, state.OCSPResponse, "the server must staple an OCSP response")
	resp, err := xocsp.ParseResponseForCert(state.OCSPResponse, state.PeerCertificates[0], issuer)
	require.NoError(tb, err)
	require.Equal(tb, xocsp.Good, resp.Status)
}

// waitNotify waits for one reload notification on ch.
func waitNotify(tb testing.TB, ch <-chan struct{}, msg string) {
	tb.Helper()
	require.Eventually(tb, func() bool {
		select {
		case <-ch:
			return true
		default:
			return false
		}
	}, waitFor, tick, msg)
}
