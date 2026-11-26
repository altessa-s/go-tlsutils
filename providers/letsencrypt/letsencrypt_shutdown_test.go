// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlsletsencrypt_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	tlsletsencrypt "github.com/altessa-s/go-tlsutils/providers/letsencrypt"
)

func TestClose_ForceClosesActiveChallengeConnection(t *testing.T) {
	t.Parallel()

	le := newProvider(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := listener.Addr().String()
	require.NoError(t, listener.Close())

	requestStarted := make(chan struct{})
	requestStopped := make(chan struct{})
	releaseHandler := make(chan struct{})

	t.Cleanup(func() { close(releaseHandler) })

	fallback := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(requestStarted)

		select {
		case <-r.Context().Done():
			close(requestStopped)
		case <-releaseHandler:
		}
	})
	require.NoError(t, le.StartHTTPServer(addr, fallback))

	requestCtx, cancelRequest := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelRequest()

	var dialer net.Dialer

	conn, err := dialer.DialContext(requestCtx, "tcp", addr)
	require.NoError(t, err)

	defer func() { _ = conn.Close() }()

	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + addr + "\r\n\r\n"))
	require.NoError(t, err)

	select {
	case <-requestStarted:
	case <-requestCtx.Done():
		t.Fatal("fallback did not receive the request")
	}

	closeCtx, cancelClose := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancelClose()

	require.ErrorIs(t, le.Close(closeCtx), context.DeadlineExceeded)

	select {
	case <-requestStopped:
	case <-requestCtx.Done():
		t.Fatal("Close did not cancel the active request")
	}

	listener, err = net.Listen("tcp", addr)
	require.NoError(t, err)
	require.NoError(t, listener.Close())
	require.NoError(t, le.Close(requestCtx))
}

func TestClose_RejectsNewServerStartsAndCertificateRequests(t *testing.T) {
	t.Parallel()

	le := newProvider(t)
	cfg, err := le.TLSConfig()
	require.NoError(t, err)
	require.NoError(t, le.Close(t.Context()))

	hello := &tls.ClientHelloInfo{ServerName: "example.com"}
	_, err = le.GetCertificate(hello)
	require.ErrorIs(t, err, tlsletsencrypt.ErrClosed)

	_, err = cfg.GetCertificate(hello)
	require.ErrorIs(t, err, tlsletsencrypt.ErrClosed)
	require.ErrorIs(t, le.StartHTTPServer("127.0.0.1:0", nil), tlsletsencrypt.ErrClosed)
}
