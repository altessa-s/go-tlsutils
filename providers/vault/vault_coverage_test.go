// Copyright 2021-2026 ALTESSA SOLUTIONS INC. All rights reserved.
// Use of this source code is governed by license that can be found in
// the LICENSE file.

package tlsvault_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-tlsutils/internal/testhelpers"
	"github.com/altessa-s/go-tlsutils/ocsp"

	tlsvault "github.com/altessa-s/go-tlsutils/providers/vault"
	vaultApi "github.com/hashicorp/vault/api"
)

// fakePKI emulates the Vault PKI sign endpoint, signing CSRs with a test CA.
type fakePKI struct {
	ca *testhelpers.CA

	mu     sync.Mutex
	paths  []string
	tokens []string
	csrs   []*x509.CertificateRequest
	fail   bool
}

func (f *fakePKI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = append(f.paths, r.Method+" "+r.URL.Path)
	f.tokens = append(f.tokens, r.Header.Get("X-Vault-Token"))
	if f.fail {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
		return
	}
	var body struct {
		CSR string `json:"csr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	block, _ := pem.Decode([]byte(body.CSR))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.csrs = append(f.csrs, csr)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.ca.Cert, csr.PublicKey, f.ca.Key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
		"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		"issuing_ca":  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.Cert.Raw})),
	}})
}

func newFakePKI(t *testing.T) (*fakePKI, *httptest.Server) {
	t.Helper()
	f := &fakePKI{ca: testhelpers.NewCA(t)}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func TestGetCertificate_IssuesFromVaultPKI(t *testing.T) {
	t.Parallel()
	f, srv := newFakePKI(t)

	v, err := tlsvault.New(
		tlsvault.WithEndpoint(srv.URL),
		tlsvault.WithStaticToken("s.static"),
		tlsvault.WithRole("web"),
		tlsvault.WithCommonName("svc.example.com"),
		tlsvault.WithSubjectAlternativeNames(" alt.example.com", "alt.example.com"),
		tlsvault.WithIPSubjectAlternativeNames("10.0.0.7"),
		tlsvault.WithRenewBefore(time.Minute),
		tlsvault.WithLogger(slog.New(slog.DiscardHandler)),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = v.Close(t.Context()) })

	cert, err := v.GetCertificate(&tls.ClientHelloInfo{ServerName: "svc.example.com"})
	require.NoError(t, err)
	require.NotNil(t, cert.Leaf)
	require.Equal(t, "svc.example.com", cert.Leaf.Subject.CommonName)
	require.Len(t, cert.Certificate, 2, "the issuing CA is appended to the chain")

	f.mu.Lock()
	require.Equal(t, []string{"PUT /v1/pki/sign/web"}, f.paths)
	require.Equal(t, []string{"s.static"}, f.tokens)
	require.Contains(t, f.csrs[0].DNSNames, "alt.example.com")
	require.True(t, f.csrs[0].IPAddresses[0].Equal(net.ParseIP("10.0.0.7")))
	f.mu.Unlock()

	// The certificate is cached: a client-certificate request reuses it.
	clientCert, err := v.GetClientCertificate(&tls.CertificateRequestInfo{})
	require.NoError(t, err)
	require.Equal(t, cert.Certificate[0], clientCert.Certificate[0])
}

func TestGetCertificate_FromClientAndCacheDir(t *testing.T) {
	t.Parallel()
	f, srv := newFakePKI(t)
	client, err := vaultApi.NewClient(&vaultApi.Config{Address: srv.URL, MaxRetries: 0})
	require.NoError(t, err)
	client.SetToken("s.client")

	v, err := tlsvault.New(
		tlsvault.WithVc(client),
		tlsvault.WithRole("svc"),
		tlsvault.WithCommonName("svc.internal"),
		tlsvault.WithCacheDir(t.TempDir()),
	)
	require.NoError(t, err)

	cert, err := v.GetClientCertificate(&tls.CertificateRequestInfo{})
	require.NoError(t, err)
	require.Equal(t, "svc.internal", cert.Leaf.Subject.CommonName)
	f.mu.Lock()
	require.Equal(t, []string{"PUT /v1/pki/sign/svc"}, f.paths)
	require.Equal(t, []string{"s.client"}, f.tokens)
	f.mu.Unlock()
}

func TestGetCertificate_IssuerError(t *testing.T) {
	t.Parallel()
	f, srv := newFakePKI(t)
	f.fail = true

	v, err := tlsvault.New(
		tlsvault.WithEndpoint(srv.URL),
		tlsvault.WithStaticToken("s.static"),
		tlsvault.WithRole("web"),
		tlsvault.WithCommonName("svc.example.com"),
	)
	require.NoError(t, err)

	_, err = v.GetCertificate(&tls.ClientHelloInfo{ServerName: "svc.example.com"})
	require.Error(t, err)
	_, err = v.GetClientCertificate(&tls.CertificateRequestInfo{})
	require.Error(t, err)
}

// failingStapler never produces a staple.
type failingStapler struct{ mode ocsp.FailureMode }

func (failingStapler) GetOCSPStaple(context.Context, *tls.Certificate) ([]byte, error) {
	return nil, errors.New("responder down")
}
func (failingStapler) RunRefreshAll(context.Context) error { return nil }
func (s failingStapler) FailureMode() ocsp.FailureMode     { return s.mode }

// stapleStapler returns a fixed staple.
type stapleStapler struct{}

func (stapleStapler) GetOCSPStaple(context.Context, *tls.Certificate) ([]byte, error) {
	return []byte("staple"), nil
}
func (stapleStapler) RunRefreshAll(context.Context) error { return nil }

// handshake runs a TLS handshake against a server configured by v and
// returns the client's view of it. Stapling runs inside a real handshake, whose
// ClientHelloInfo carries a context.
func handshake(t *testing.T, v *tlsvault.Vault) (tls.ConnectionState, error) {
	t.Helper()
	serverCfg, err := v.TLSConfig()
	require.NoError(t, err)
	cConn, sConn := net.Pipe()
	t.Cleanup(func() { _ = cConn.Close(); _ = sConn.Close() })

	srv := tls.Server(sConn, serverCfg)
	done := make(chan error, 1)
	go func() { done <- srv.HandshakeContext(t.Context()) }()

	//nolint:gosec // the test inspects the stapled response, not the chain
	client := tls.Client(cConn, &tls.Config{ServerName: "svc.example.com", InsecureSkipVerify: true})
	cErr := client.HandshakeContext(t.Context())
	if cErr != nil {
		_ = cConn.Close()
	}
	sErr := <-done
	if sErr != nil {
		return tls.ConnectionState{}, sErr
	}
	return client.ConnectionState(), cErr
}

func TestGetCertificate_OCSPStapling(t *testing.T) {
	t.Parallel()
	_, srv := newFakePKI(t)
	newProvider := func(t *testing.T, opt tlsvault.Option) *tlsvault.Vault {
		t.Helper()
		v, err := tlsvault.New(
			tlsvault.WithEndpoint(srv.URL),
			tlsvault.WithStaticToken("s.static"),
			tlsvault.WithRole("web"),
			tlsvault.WithCommonName("svc.example.com"),
			opt,
		)
		require.NoError(t, err)
		return v
	}

	state, err := handshake(t, newProvider(t, tlsvault.WithOcspStapler(stapleStapler{})))
	require.NoError(t, err)
	require.Equal(t, []byte("staple"), state.OCSPResponse)

	state, err = handshake(t, newProvider(t, tlsvault.WithOcspStapler(failingStapler{mode: ocsp.FailureModeSoft})))
	require.NoError(t, err)
	require.Empty(t, state.OCSPResponse, "soft mode serves the certificate without a staple")

	_, err = handshake(t, newProvider(t, tlsvault.WithOcspStapler(failingStapler{mode: ocsp.FailureModeHard})))
	require.Error(t, err, "a hard-fail stapler aborts the handshake")
}

func TestNew_OptionErrors(t *testing.T) {
	t.Parallel()
	_, err := tlsvault.New(tlsvault.WithIPSubjectAlternativeNames("not-an-ip"))
	require.ErrorIs(t, err, tlsvault.ErrInvalidIP)

	_, err = tlsvault.New(tlsvault.WithEndpoint("://bad"))
	require.ErrorIs(t, err, tlsvault.ErrInvalidEndpoint)
}

func TestWithRenewableToken_RejectsMissingToken(t *testing.T) {
	t.Parallel()
	for name, tok := range map[string]*tlsvault.Token{
		"nil":           nil,
		"zero value":    {},
		"empty initial": tlsvault.NewToken("", time.Hour, time.Minute),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := tlsvault.New(tlsvault.WithRenewableToken(tok))
			require.ErrorIs(t, err, tlsvault.ErrInvalidToken)
		})
	}
}

func TestClose_RenewableTokenNeverAuthenticated(t *testing.T) {
	t.Parallel()
	v, err := tlsvault.New(
		tlsvault.WithEndpoint("http://127.0.0.1:1"),
		tlsvault.WithRenewableToken(tlsvault.NewToken("s.renew", time.Hour, time.Minute)),
		tlsvault.WithRole("web"),
	)
	require.NoError(t, err)
	require.NoError(t, v.Close(t.Context()))
}

// newRenewableVault serves token lookup-self (renewable, 1h TTL) in front of
// the fake PKI so a renewable token can authenticate.
func newRenewableVault(t *testing.T) (*fakePKI, *httptest.Server) {
	t.Helper()
	f := &fakePKI{ca: testhelpers.NewCA(t)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/auth/token/lookup-self", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		fail := f.fail
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if fail {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"renewable":true,"ttl":3600}}`))
	})
	mux.Handle("/", f)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return f, srv
}

func TestClose_RenewableTokenAuthenticated(t *testing.T) {
	t.Parallel()
	f, srv := newRenewableVault(t)
	v, err := tlsvault.New(
		tlsvault.WithEndpoint(srv.URL),
		tlsvault.WithRenewableToken(tlsvault.NewToken("s.renew", time.Hour, time.Minute)),
		tlsvault.WithRole("web"),
		tlsvault.WithCommonName("svc.example.com"),
	)
	require.NoError(t, err)

	_, err = v.GetCertificate(&tls.ClientHelloInfo{ServerName: "svc.example.com"})
	require.NoError(t, err)
	f.mu.Lock()
	require.Equal(t, []string{"s.renew"}, f.tokens, "the PKI request carries the renewable token")
	f.mu.Unlock()

	require.NoError(t, v.Close(t.Context()))
	require.NoError(t, v.Close(t.Context()), "Close is idempotent")
}

func TestClose_RenewableTokenFailedAuthentication(t *testing.T) {
	t.Parallel()
	f, srv := newRenewableVault(t)
	f.fail = true
	v, err := tlsvault.New(
		tlsvault.WithEndpoint(srv.URL),
		tlsvault.WithRenewableToken(tlsvault.NewToken("s.renew", time.Hour, time.Minute)),
		tlsvault.WithRole("web"),
		tlsvault.WithCommonName("svc.example.com"),
	)
	require.NoError(t, err)

	// The first issuance fails token lookup; the second gets past the
	// one-shot setup without starting renewal.
	_, err = v.GetCertificate(&tls.ClientHelloInfo{ServerName: "svc.example.com"})
	require.Error(t, err)
	_, err = v.GetCertificate(&tls.ClientHelloInfo{ServerName: "svc.example.com"})
	require.Error(t, err)

	require.NoError(t, v.Close(t.Context()))
}

func TestGetCertificate_StaplesWithoutHandshakeContext(t *testing.T) {
	t.Parallel()
	_, srv := newFakePKI(t)
	v, err := tlsvault.New(
		tlsvault.WithEndpoint(srv.URL),
		tlsvault.WithStaticToken("s.static"),
		tlsvault.WithRole("web"),
		tlsvault.WithCommonName("svc.example.com"),
		tlsvault.WithOcspStapler(stapleStapler{}),
	)
	require.NoError(t, err)

	cert, err := v.GetCertificate(&tls.ClientHelloInfo{ServerName: "svc.example.com"})
	require.NoError(t, err)
	require.Equal(t, []byte("staple"), cert.OCSPStaple)

	cert, err = v.GetClientCertificate(&tls.CertificateRequestInfo{})
	require.NoError(t, err)
	require.Equal(t, []byte("staple"), cert.OCSPStaple)
}

func TestGetCertificate_NilHandshakeInfo(t *testing.T) {
	t.Parallel()
	v, err := tlsvault.New(tlsvault.WithStaticToken("s.static"))
	require.NoError(t, err)

	_, err = v.GetCertificate(nil)
	require.ErrorIs(t, err, tlsvault.ErrNilHandshakeInfo)
	_, err = v.GetClientCertificate(nil)
	require.ErrorIs(t, err, tlsvault.ErrNilHandshakeInfo)
}

func TestLogger_EmitsFieldsAtEnabledLevels(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := tlsvault.NewLoggerWithContext(t.Context(),
		slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	l.Trace("trace", map[string]any{"a": 1})
	l.Debug("debug")
	l.Info("info", map[string]any{"b": "x"}, map[string]any{"c": true})
	l.Warn("warn", map[string]any{"d": 2})
	l.Error("error")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 5)
	require.Contains(t, lines[0], `"level":"DEBUG"`)
	require.Contains(t, lines[0], `"a":1`)
	require.Contains(t, lines[2], `"b":"x"`)
	require.Contains(t, lines[2], `"c":true`)
	require.Contains(t, lines[3], `"level":"WARN"`)
	require.Contains(t, lines[4], `"level":"ERROR"`)

	// Disabled levels emit nothing.
	buf.Reset()
	quiet := tlsvault.NewLogger(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError})))
	quiet.Debug("hidden", map[string]any{"x": 1})
	quiet.Info("hidden")
	require.Empty(t, buf.String())
}
