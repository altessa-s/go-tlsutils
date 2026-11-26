// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlsletsencrypt

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"

	coreerrs "github.com/altessa-s/go-atlas-core/errors"
	tlsutils "github.com/altessa-s/go-tlsutils"
	tlsproviders "github.com/altessa-s/go-tlsutils/providers"
)

// LetsEncrypt provides automatic TLS certificate management using the ACME protocol
// and Let's Encrypt certificate authority. Use New to create a new instance.
type LetsEncrypt struct {
	opts    *options
	am      *autocert.Manager
	httpSrv *challengeServer
	mu      sync.Mutex
	closed  bool
}

type challengeServer struct {
	server       http.Server
	cancelListen context.CancelFunc
	done         chan struct{}
}

// New creates a new Let's Encrypt TLS certificate provider.
// The provider uses HTTP-01 challenges which require port 80 to be accessible.
//
// Example:
//
//	provider, err := tlsletsencrypt.New(
//		tlsletsencrypt.WithDomains("example.com"),
//		tlsletsencrypt.WithEmail("admin@example.com"),
//		tlsletsencrypt.WithCacheDir("./certs"),
//	)
func New(opt ...Option) (*LetsEncrypt, error) {
	opts, err := newOptions(opt...)
	if err != nil {
		return nil, err
	}

	if opts.logger == nil {
		opts.logger = slog.New(slog.DiscardHandler)
	}

	if err := opts.validate(); err != nil {
		return nil, err
	}

	le := &LetsEncrypt{opts: opts}
	le.initAutocertManager()

	return le, nil
}

func (le *LetsEncrypt) initAutocertManager() {
	am := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Email:      le.opts.email,
		HostPolicy: autocert.HostWhitelist(le.opts.domains...),
		Client:     le.opts.client,
	}
	if le.opts.renewBefore > 0 {
		am.RenewBefore = le.opts.renewBefore
	}

	if le.opts.cacheDir != "" {
		am.Cache = autocert.DirCache(le.opts.cacheDir)
	}

	le.am = am
}

// StartHTTPServer starts the ACME HTTP server for handling HTTP-01 challenges.
// The server must be accessible on port 80 from the internet for challenge validation.
// The port in addr is honored (e.g. ":8080" behind a port-forwarding load balancer);
// a host-only or empty addr listens on port 80.
// The fallback handler receives non-ACME requests.
//
// Example:
//
//	go provider.StartHTTPServer(":80", nil)
//
// Example with HTTP to HTTPS redirect:
//
//	redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		http.Redirect(w, r, "https://"+r.Host+r.URL.Path, http.StatusMovedPermanently)
//	})
//	go provider.StartHTTPServer(":80", redirect)
func (le *LetsEncrypt) StartHTTPServer(addr string, fallback http.Handler) error {
	return le.StartHTTPServerWithContext(context.Background(), addr, fallback)
}

var (
	// ErrNilHTTPServerContext is returned when a nil context is provided to StartHTTPServerWithContext.
	ErrNilHTTPServerContext = errors.New("acme http server: context cannot be nil")
	// ErrHTTPServerStarted is returned when attempting to start an already running HTTP server.
	ErrHTTPServerStarted = errors.New("acme http server: already started")
	// ErrClosed is returned when a closed provider is asked to start a
	// server or retrieve a certificate.
	ErrClosed = errors.New("letsencrypt: provider is closed")
)

// listenAddr resolves the address the ACME HTTP server listens on. A port in
// addr is honored; a host-only or empty addr listens on the HTTP port (80),
// where ACME HTTP-01 validation connects.
func listenAddr(addr string) string {
	if host, port, err := net.SplitHostPort(addr); err == nil {
		if port == "" {
			port = "http"
		}

		return net.JoinHostPort(host, port)
	}
	// Accept host-only addresses too (e.g. "0.0.0.0", "localhost", "::").
	return net.JoinHostPort(strings.Trim(addr, "[]"), "http")
}

// StartHTTPServerWithContext starts the ACME HTTP server with context support.
// The context enables graceful shutdown and cancellation.
//
// Example:
//
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//	go provider.StartHTTPServerWithContext(ctx, ":80", nil)
func (le *LetsEncrypt) StartHTTPServerWithContext(ctx context.Context, addr string, fallback http.Handler) error {
	if ctx == nil {
		return ErrNilHTTPServerContext
	}

	// Check context before starting
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	le.mu.Lock()
	if le.closed {
		le.mu.Unlock()
		return ErrClosed
	}

	if le.httpSrv != nil {
		le.mu.Unlock()
		return ErrHTTPServerStarted
	}

	// Reserve the server before binding so Close can cancel an in-progress listen.
	listenCtx, cancelListen := context.WithCancel(ctx)
	srv := &challengeServer{
		server: http.Server{
			MaxHeaderBytes: 1 << 16,           //nolint:mnd
			ReadTimeout:    30 * time.Second,  //nolint:mnd
			WriteTimeout:   30 * time.Second,  //nolint:mnd
			IdleTimeout:    120 * time.Second, //nolint:mnd
		},
		cancelListen: cancelListen,
		done:         make(chan struct{}),
	}
	le.httpSrv = srv
	le.mu.Unlock()

	var config net.ListenConfig

	listener, err := config.Listen(listenCtx, "tcp", listenAddr(addr))

	cancelListen()

	if err != nil {
		le.finishHTTPServer(srv)
		return coreerrs.Wrap(err, "acme http server") //nolint:err113
	}

	srv.server.Handler = le.am.HTTPHandler(fallback)
	shutdownDone := make(chan struct{})
	stopShutdown := context.AfterFunc(ctx, func() {
		defer close(shutdownDone)
		// Keep logging and tracing values while allowing time for graceful shutdown.
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), le.opts.httpShutdownTimeout)
		defer cancel()

		_ = srv.shutdown(shutdownCtx)
	})

	go func() {
		defer le.finishHTTPServer(srv)

		if err := srv.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			_ = srv.server.Close() // #nosec G104 -- best effort close

			le.opts.logger.ErrorContext(ctx, "acme http server stopped with error", slog.Any("error", err))
		}

		if !stopShutdown() {
			<-shutdownDone
		}
	}()

	le.opts.logger.InfoContext(ctx, "acme HTTP server started", slog.String("address", listener.Addr().String()))

	return nil
}

func (le *LetsEncrypt) finishHTTPServer(srv *challengeServer) {
	le.mu.Lock()
	defer le.mu.Unlock()

	// Keep the server available to concurrent Close calls while it drains.
	if !le.closed {
		le.httpSrv = nil
	}

	close(srv.done)
}

func (srv *challengeServer) shutdown(ctx context.Context) error {
	err := srv.server.Shutdown(ctx)
	if err != nil {
		_ = srv.server.Close() // #nosec G104 -- best effort close
	}

	return err
}

// HTTPHandler returns an HTTP handler that responds to ACME HTTP-01 challenges.
// Non-ACME requests are forwarded to the fallback handler.
//
// Example:
//
//	mux := http.NewServeMux()
//	http.ListenAndServe(":80", provider.HTTPHandler(mux))
func (le *LetsEncrypt) HTTPHandler(fallback http.Handler) http.Handler {
	return le.am.HTTPHandler(fallback)
}

// TLSConfig returns a TLS configuration with automatic certificate management.
// The configuration uses secure defaults and handles certificate renewal automatically.
//
// Example:
//
//	tlsConfig, err := provider.TLSConfig()
//	if err != nil {
//		log.Fatal(err)
//	}
//	server := &http.Server{
//		Addr:      ":443",
//		TLSConfig: tlsConfig,
//		Handler:   handler,
//	}
//	server.ListenAndServeTLS("", "")
func (le *LetsEncrypt) TLSConfig() (*tls.Config, error) {
	// Get autocert manager's TLS config
	tlsConfig := le.am.TLSConfig()

	tlsConfig.GetCertificate = le.GetCertificate
	// Apply secure defaults from tlsutils.
	tlsConfig.MinVersion = tls.VersionTLS12
	tlsConfig.CipherSuites = tlsutils.DefaultTLSConfig().CipherSuites

	return tlsConfig, nil
}

// GetCertificate retrieves or requests a certificate for the given domain.
// This method implements the tls.Config.GetCertificate callback.
//
// Example:
//
//	config := &tls.Config{GetCertificate: provider.GetCertificate}
func (le *LetsEncrypt) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	le.mu.Lock()
	closed := le.closed
	le.mu.Unlock()

	if closed {
		return nil, ErrClosed
	}

	return le.am.GetCertificate(hello)
}

// Close stops the HTTP challenge server and waits for its goroutines until ctx
// is done. If graceful shutdown fails, Close force-closes active connections.
// The provider rejects new server starts and certificate requests after closing.
// The upstream autocert API has no way to stop its internal renewal timer once
// started. The timer continues running until process exit.
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//	provider.Close(ctx)
func (le *LetsEncrypt) Close(ctx context.Context) error {
	le.mu.Lock()
	le.closed = true
	srv := le.httpSrv
	le.mu.Unlock()

	if srv == nil {
		return nil
	}

	srv.cancelListen()

	if err := srv.shutdown(ctx); err != nil {
		return err
	}

	select {
	case <-srv.done:
	case <-ctx.Done():
		return ctx.Err()
	}

	le.mu.Lock()
	le.httpSrv = nil
	le.mu.Unlock()

	return nil
}

// Type returns the provider type identifier.
// Always returns ProviderTypeLetsEncrypt.
//
// Example:
//
//	fmt.Println(provider.Type()) // "letsencrypt"
func (le *LetsEncrypt) Type() tlsproviders.ProviderType {
	return tlsproviders.ProviderTypeLetsEncrypt
}

// Ensure LetsEncrypt implements required interfaces
var _ tlsproviders.Certificate = (*LetsEncrypt)(nil)
var _ tlsproviders.Provider = (*LetsEncrypt)(nil)
