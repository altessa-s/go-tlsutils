// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlsletsencrypt_test

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"golang.org/x/crypto/acme"

	tlsproviders "github.com/altessa-s/go-tlsutils/providers"
	tlsletsencrypt "github.com/altessa-s/go-tlsutils/providers/letsencrypt"
)

func newProvider(t *testing.T, extra ...tlsletsencrypt.Option) *tlsletsencrypt.LetsEncrypt {
	t.Helper()
	opts := append([]tlsletsencrypt.Option{
		tlsletsencrypt.WithDomains("example.com", " www.example.com "),
		tlsletsencrypt.WithEmail("admin@example.com"),
		tlsletsencrypt.WithCacheDir(t.TempDir()),
		tlsletsencrypt.WithRenewBefore(48 * time.Hour),
		// The ACME directory is never contacted by these tests.
		tlsletsencrypt.WithClient(&acme.Client{DirectoryURL: "http://127.0.0.1:1/directory"}),
		tlsletsencrypt.WithLogger(slog.New(slog.DiscardHandler)),
		tlsletsencrypt.WithHTTPShutdownTimeout(time.Second),
	}, extra...)
	le, err := tlsletsencrypt.New(opts...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = le.Close(context.Background()) })
	return le
}

func TestNew_RequiresDomainsAndEmail(t *testing.T) {
	t.Parallel()
	_, err := tlsletsencrypt.New(tlsletsencrypt.WithEmail("admin@example.com"))
	require.ErrorIs(t, err, tlsletsencrypt.ErrNoDomains)

	_, err = tlsletsencrypt.New(tlsletsencrypt.WithDomains("example.com"))
	require.ErrorIs(t, err, tlsletsencrypt.ErrNoEmail)

	// A logger is optional.
	le, err := tlsletsencrypt.New(tlsletsencrypt.WithDomains("example.com"), tlsletsencrypt.WithEmail("a@example.com"))
	require.NoError(t, err)
	require.NoError(t, le.Close(t.Context()))
}

func TestTLSConfig_SecureDefaultsAndACMEALPN(t *testing.T) {
	t.Parallel()
	le := newProvider(t)
	require.Equal(t, tlsproviders.ProviderTypeLetsEncrypt, le.Type())

	cfg, err := le.TLSConfig()
	require.NoError(t, err)
	require.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	require.NotEmpty(t, cfg.CipherSuites)
	require.True(t, slices.Contains(cfg.NextProtos, acme.ALPNProto), "TLS-ALPN-01 must be negotiable")
	require.NotNil(t, cfg.GetCertificate)
}

// A host outside the configured domains is refused by the host policy
// before any ACME traffic.
func TestGetCertificate_RejectsUnknownHost(t *testing.T) {
	t.Parallel()
	le := newProvider(t)

	_, err := le.GetCertificate(&tls.ClientHelloInfo{ServerName: "evil.example.org"})
	require.Error(t, err)

	_, err = le.GetCertificate(&tls.ClientHelloInfo{})
	require.Error(t, err, "a handshake without SNI cannot be served")
}

func TestHTTPHandler_FallbackAndChallenge(t *testing.T) {
	t.Parallel()
	le := newProvider(t)
	fallback := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "fallback")
	})
	h := le.HTTPHandler(fallback)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/page", nil))
	require.Equal(t, "fallback", rec.Body.String())

	// An unknown challenge token is not served from the fallback.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/unknown", nil))
	require.Equal(t, http.StatusNotFound, rec.Code)
	require.NotEqual(t, "fallback", rec.Body.String())
}

func TestStartHTTPServerWithContext_CanceledContext(t *testing.T) {
	t.Parallel()
	le := newProvider(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, le.StartHTTPServerWithContext(ctx, "127.0.0.1:80", nil), context.Canceled)
}

func TestOptions_BlankAndPointerValues(t *testing.T) {
	t.Parallel()
	email := " admin@example.com "
	blank := "   "
	dir := t.TempDir()

	// Blank or nil values leave the option unset, so the email stays missing.
	for _, opt := range []tlsletsencrypt.Option{
		tlsletsencrypt.WithEmail("  "),
		tlsletsencrypt.WithEmail(&blank),
		tlsletsencrypt.WithEmail((*string)(nil)),
	} {
		_, err := tlsletsencrypt.New(tlsletsencrypt.WithDomains("example.com"), opt)
		require.ErrorIs(t, err, tlsletsencrypt.ErrNoEmail)
	}

	le, err := tlsletsencrypt.New(
		tlsletsencrypt.WithDomains("example.com"),
		tlsletsencrypt.WithEmail(&email),
		tlsletsencrypt.WithCacheDir(&dir),
		tlsletsencrypt.WithCacheDir(&blank),
		tlsletsencrypt.WithCacheDir((*string)(nil)),
		tlsletsencrypt.WithCacheDir(""),
		tlsletsencrypt.WithClient(nil),
		tlsletsencrypt.WithLogger(nil),
		tlsletsencrypt.WithRenewBefore(0),
		tlsletsencrypt.WithHTTPShutdownTimeout(0),
	)
	require.NoError(t, err)
	require.NoError(t, le.Close(t.Context()))

	_, err = tlsletsencrypt.New(tlsletsencrypt.WithDomains(), tlsletsencrypt.WithEmail("a@example.com"))
	require.ErrorIs(t, err, tlsletsencrypt.ErrNoDomains)
}

func TestStartHTTPServerWithContext_HonorsPort(t *testing.T) {
	t.Parallel()
	le := newProvider(t)

	// Reserve a free port, then hand it to the server.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())

	fallback := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	require.NoError(t, le.StartHTTPServerWithContext(t.Context(), addr, fallback))

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+"/", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "the server listens on the configured port")
	_ = resp.Body.Close()
	require.Equal(t, http.StatusTeapot, resp.StatusCode)
}

// TestClose_StopsShutdownWatcher is serial: it counts process-wide goroutines,
// so a parallel test with its own running server would skew the count.
func TestClose_StopsShutdownWatcher(t *testing.T) {
	le := newProvider(t)

	// A context that is never canceled: only Close may stop the server.
	require.NoError(t, le.StartHTTPServerWithContext(context.Background(), "127.0.0.1:0", nil))
	require.NoError(t, le.Close(t.Context()))

	require.Eventually(t, func() bool {
		buf := make([]byte, 1<<20)
		stacks := string(buf[:runtime.Stack(buf, true)])
		return !strings.Contains(stacks, "(*LetsEncrypt).StartHTTPServerWithContext.func")
	}, 2*time.Second, 10*time.Millisecond, "server goroutines must exit after Close")
}
