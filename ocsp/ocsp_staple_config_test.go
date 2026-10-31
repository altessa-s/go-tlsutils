// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package ocsp

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-tlsutils/internal/testhelpers"
)

// TestStapleOrEnforce_HardModeEmptyResponse pins the Hard-mode branch taken
// when the stapler fails open with a nil error but no staple (as opposed to
// a reported fetch error): the handshake must still be rejected, with a
// message distinguishing this case from a wrapped fetch error.
func TestStapleOrEnforce_HardModeEmptyResponse(t *testing.T) {
	t.Parallel()

	stapler := &failingStapler{failureMode: FailureModeHard}
	cert := &tls.Certificate{Certificate: [][]byte{{0x01}}}

	got, err := stapleOrEnforce(t.Context(), stapler, cert)
	require.Error(t, err)
	require.Nil(t, got)
	require.ErrorContains(t, err, "empty response")
}

// TestStapleOCSPToConfig_OriginalGetCertificateSuccess pins the passthrough
// of a non-nil certificate from a caller-supplied GetCertificate: the wrapped
// callback must staple whatever the original returns, not just its own
// static certificates. A real handshake is required because a bare
// *tls.ClientHelloInfo carries a nil internal context, and the wrapped
// callback applies a timeout to it.
func TestStapleOCSPToConfig_OriginalGetCertificateSuccess(t *testing.T) {
	t.Parallel()
	ca := testhelpers.NewCA(t)
	r := newCountingResponder(t, ca, 3*time.Hour)
	cert := chainWith(t, ca, r.srv.URL)

	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil },
	}
	require.NoError(t, StapleOCSPToConfig(cfg, NewOCSPStapler()))

	state, err := handshakeNoSNI(t, cfg, noSNIClient())
	require.NoError(t, err)
	require.Equal(t, cert.Certificate[0], state.PeerCertificates[0].Raw)
	require.NotEmpty(t, state.OCSPResponse, "the original GetCertificate's certificate must be stapled")
}

// TestStapleOCSPToConfig_OriginalGetCertificateError pins error propagation
// from a caller-supplied GetCertificate: a lookup failure in the original
// callback must abort the handshake, not be swallowed or replaced by a
// stapling-related error.
func TestStapleOCSPToConfig_OriginalGetCertificateError(t *testing.T) {
	t.Parallel()
	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, errors.New("lookup failed") },
	}
	require.NoError(t, StapleOCSPToConfig(cfg, NewOCSPStapler()))

	_, err := handshakeNoSNI(t, cfg, noSNIClient())
	require.Error(t, err, "an error from the original GetCertificate must abort the handshake")
}

// clientCertHandshake runs a real TLS handshake over an in-memory pipe with a
// server that requests (but does not verify) a client certificate, so the
// wrapped GetClientCertificate installed by StapleOCSPToConfig is invoked
// with a real, context-bearing *tls.CertificateRequestInfo — a zero-value
// one has a nil internal context and panics on the timeout it applies.
// It returns the client-side handshake error and, on success, the
// certificate the server received.
func clientCertHandshake(t *testing.T, serverCert tls.Certificate, clientCfg *tls.Config) ([][]byte, error) {
	t.Helper()
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	cConn, sConn := net.Pipe()
	srv := tls.Server(sConn, serverCfg)
	cli := tls.Client(cConn, clientCfg)
	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		_ = srv.HandshakeContext(t.Context())
		_ = sConn.Close()
	}()

	err := cli.HandshakeContext(t.Context())
	_ = cConn.Close()
	<-srvDone
	if err != nil {
		return nil, err
	}
	peers := srv.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		return nil, nil
	}
	return [][]byte{peers[0].Raw}, nil
}

// TestStapleOCSPToConfig_WrapsOriginalGetClientCertificate pins the branch
// that wraps a caller-supplied GetClientCertificate (as opposed to the
// static-certificate fallback): the server must receive the certificate the
// original callback selected, staple included.
func TestStapleOCSPToConfig_WrapsOriginalGetClientCertificate(t *testing.T) {
	t.Parallel()
	ca := testhelpers.NewCA(t)
	r := newCountingResponder(t, ca, 3*time.Hour)
	clientCert := chainWith(t, ca, r.srv.URL)
	_, _, serverCert := testhelpers.SelfSignedCert(t)

	clientCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test: no server CA to verify against
		MinVersion:         tls.VersionTLS12,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return clientCert, nil
		},
	}
	require.NoError(t, StapleOCSPToConfig(clientCfg, NewOCSPStapler()))

	peerRaw, err := clientCertHandshake(t, serverCert, clientCfg)
	require.NoError(t, err)
	require.Equal(t, clientCert.Certificate[0], peerRaw[0],
		"the server must receive the certificate the wrapped GetClientCertificate returned")
}

// TestStapleOCSPToConfig_OriginalGetClientCertificateError pins error
// propagation through the wrapped GetClientCertificate: a failure from the
// original callback must abort the handshake with that same error.
func TestStapleOCSPToConfig_OriginalGetClientCertificateError(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("no client certificate available")
	_, _, serverCert := testhelpers.SelfSignedCert(t)

	clientCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test: no server CA to verify against
		MinVersion:         tls.VersionTLS12,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return nil, wantErr
		},
	}
	require.NoError(t, StapleOCSPToConfig(clientCfg, NewOCSPStapler()))

	_, err := clientCertHandshake(t, serverCert, clientCfg)
	require.ErrorIs(t, err, wantErr, "an error from the original GetClientCertificate must propagate and abort the handshake")
}
