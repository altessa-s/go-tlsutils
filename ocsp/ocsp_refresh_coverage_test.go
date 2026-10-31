// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package ocsp

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-tlsutils/internal/testhelpers"

	xocsp "golang.org/x/crypto/ocsp"
)

// countingResponder serves CA-signed OCSP responses whose status and
// nextUpdate are read per request; fail makes it answer 500.
type countingResponder struct {
	srv        *httptest.Server
	hits       atomic.Int32
	fail       atomic.Bool
	status     atomic.Int32
	nextUpdate atomic.Int64 // offset from now, nanoseconds
}

func newCountingResponder(t testing.TB, ca *testhelpers.CA, nextUpdate time.Duration) *countingResponder {
	t.Helper()
	r := &countingResponder{}
	r.status.Store(int32(xocsp.Good))
	r.nextUpdate.Store(int64(nextUpdate))
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits.Add(1)
		if r.fail.Load() {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		parsed, err := xocsp.ParseRequest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		now := time.Now()
		resp := xocsp.Response{
			Status:       int(r.status.Load()),
			SerialNumber: parsed.SerialNumber,
			ThisUpdate:   now.Add(-time.Minute),
			NextUpdate:   now.Add(time.Duration(r.nextUpdate.Load())),
		}
		if resp.Status == xocsp.Revoked {
			resp.RevokedAt = now.Add(-time.Hour)
		}
		der, err := xocsp.CreateResponse(ca.Cert, ca.Cert, resp, ca.Key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(der)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func chainWith(t testing.TB, ca *testhelpers.CA, urls ...string) *tls.Certificate {
	t.Helper()
	leaf := ca.SignLeaf(t, testhelpers.WithOCSPServers(urls...))
	leaf.Certificate = append(leaf.Certificate, ca.Cert.Raw)
	return &leaf
}

func TestNeedsRefreshAndRunRefreshCycle(t *testing.T) {
	t.Parallel()
	ca := testhelpers.NewCA(t)
	r := newCountingResponder(t, ca, 3*time.Hour)
	cert := chainWith(t, ca, r.srv.URL)
	s := NewOCSPStapler(WithLogger(slog.New(slog.DiscardHandler)))

	require.True(t, s.NeedsRefresh(cert), "an uncached certificate needs a refresh")

	// Not cached yet: the cycle fetches and caches.
	require.NoError(t, s.RunRefreshCycle(t.Context(), cert))
	require.Equal(t, int32(1), r.hits.Load())
	require.False(t, s.NeedsRefresh(cert))

	// Fresh: nothing is fetched.
	require.NoError(t, s.RunRefreshCycle(t.Context(), cert))
	require.Equal(t, int32(1), r.hits.Load())

	// Close to expiry: the cycle refetches and updates the entry.
	s.mu.RLock()
	entry := s.cache[cacheKeyOf(cert)]
	s.mu.RUnlock()
	entry.mu.Lock()
	entry.nextUpdate = time.Now().Add(10 * time.Minute)
	entry.mu.Unlock()
	require.True(t, s.NeedsRefresh(cert))

	require.NoError(t, s.RunRefreshCycle(t.Context(), cert))
	require.Equal(t, int32(2), r.hits.Load())
	require.False(t, s.NeedsRefresh(cert))

	// A failing responder surfaces the error and keeps the old entry.
	entry.mu.Lock()
	entry.nextUpdate = time.Now().Add(10 * time.Minute)
	old := entry.response
	entry.mu.Unlock()
	r.fail.Store(true)
	require.Error(t, s.RunRefreshCycle(t.Context(), cert))
	entry.mu.RLock()
	require.Equal(t, old, entry.response)
	entry.mu.RUnlock()

	// A malformed leaf cannot be refreshed.
	bad := &tls.Certificate{Certificate: [][]byte{[]byte("junk")}}
	s.mu.Lock()
	s.cache[cacheKeyOf(bad)] = &ocspCacheEntry{nextUpdate: time.Now()}
	s.mu.Unlock()
	require.Error(t, s.RunRefreshCycle(t.Context(), bad))
}

func cacheKeyOf(cert *tls.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Certificate[0])
}

func TestRunRefreshAll_RefreshesCachedAndJoinsErrors(t *testing.T) {
	t.Parallel()
	ca := testhelpers.NewCA(t)
	good := newCountingResponder(t, ca, 3*time.Hour)
	flaky := newCountingResponder(t, ca, 3*time.Hour)
	s := NewOCSPStapler()

	c1 := chainWith(t, ca, good.srv.URL)
	c2 := chainWith(t, ca, flaky.srv.URL)
	_, err := s.GetOCSPStaple(t.Context(), c1)
	require.NoError(t, err)
	_, err = s.GetOCSPStaple(t.Context(), c2)
	require.NoError(t, err)

	s.mu.RLock()
	for _, e := range s.cache {
		e.mu.Lock()
		e.nextUpdate = time.Now().Add(time.Minute)
		e.mu.Unlock()
	}
	s.mu.RUnlock()
	flaky.fail.Store(true)

	err = s.RunRefreshAll(t.Context())
	require.Error(t, err)
	require.Equal(t, int32(2), good.hits.Load())
	require.Equal(t, int32(2), flaky.hits.Load())
	require.False(t, s.NeedsRefresh(c1))
	require.True(t, s.NeedsRefresh(c2))
}

func TestRefreshAllFunc_RefreshesCache(t *testing.T) {
	t.Parallel()
	ca := testhelpers.NewCA(t)
	r := newCountingResponder(t, ca, 3*time.Hour)
	s := NewOCSPStapler()

	cert := chainWith(t, ca, r.srv.URL)
	_, err := s.GetOCSPStaple(t.Context(), cert)
	require.NoError(t, err)
	s.mu.RLock()
	for _, e := range s.cache {
		e.mu.Lock()
		e.nextUpdate = time.Now().Add(time.Minute)
		e.mu.Unlock()
	}
	s.mu.RUnlock()

	fn := s.RefreshAllFunc()
	require.NoError(t, s.RunRefreshAll(t.Context()), "RefreshAllFunc alone does not mark the refresh scheduler-managed")
	require.Equal(t, int32(2), r.hits.Load())

	s.MarkSchedulerManaged()
	require.ErrorIs(t, s.RunRefreshAll(t.Context()), ErrSchedulerManaged)
	s.mu.RLock()
	for _, e := range s.cache {
		e.mu.Lock()
		e.nextUpdate = time.Now().Add(time.Minute)
		e.mu.Unlock()
	}
	s.mu.RUnlock()
	require.NoError(t, fn(t.Context()))
	require.Equal(t, int32(3), r.hits.Load(), "the scheduler func still refreshes the cache")
}

type countingTransport struct {
	n atomic.Int32
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	return http.DefaultTransport.RoundTrip(r)
}

// gatedTransport holds every request until release is closed and reports the
// first one on entered.
type gatedTransport struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *gatedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	g.once.Do(func() { close(g.entered) })
	<-g.release
	return http.DefaultTransport.RoundTrip(r)
}

func TestGetOCSPStaple_SharesConcurrentFetch(t *testing.T) {
	t.Parallel()
	ca := testhelpers.NewCA(t)
	r := newCountingResponder(t, ca, 3*time.Hour)
	cert := chainWith(t, ca, r.srv.URL)
	gate := &gatedTransport{entered: make(chan struct{}), release: make(chan struct{})}
	s := NewOCSPStapler(WithHTTPClient(&http.Client{Transport: gate}))

	const callers = 16
	var wg sync.WaitGroup
	staples := make([][]byte, callers)
	errs := make([]error, callers)
	for i := range callers {
		wg.Go(func() { staples[i], errs[i] = s.GetOCSPStaple(t.Context(), cert) })
	}
	<-gate.entered
	close(gate.release)
	wg.Wait()

	for i := range callers {
		require.NoError(t, errs[i])
		require.Equal(t, staples[0], staples[i])
	}
	require.Equal(t, int32(1), r.hits.Load(), "concurrent cache misses share one fetch")
}

// TestGetOCSPStaple_SharedFetchKeepsCallerDeadline pins the deadline handling
// of the shared fetch: the first caller's deadline still bounds it, and no
// group-level ceiling shortens a longer budget.
func TestGetOCSPStaple_SharedFetchKeepsCallerDeadline(t *testing.T) {
	t.Parallel()
	ca := testhelpers.NewCA(t)
	r := newCountingResponder(t, ca, 3*time.Hour)
	cert := chainWith(t, ca, r.srv.URL)

	gate := &gatedTransport{entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() { close(gate.release) })
	s := NewOCSPStapler(WithHTTPClient(&http.Client{Transport: gate}))
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, err := s.GetOCSPStaple(ctx, cert)
	require.ErrorIs(t, err, context.DeadlineExceeded, "the caller stops waiting at its own deadline")

	var seen time.Time
	ok := NewOCSPStapler(WithHTTPClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		seen, _ = req.Context().Deadline()
		return http.DefaultTransport.RoundTrip(req)
	})}))
	ctx, cancel = context.WithTimeout(t.Context(), time.Hour)
	defer cancel()
	deadline, _ := ctx.Deadline()
	_, err = ok.GetOCSPStaple(ctx, cert)
	require.NoError(t, err)
	require.Equal(t, deadline, seen, "the request runs under the caller's deadline, not a shorter group timeout")
}

// TestGetOCSPStaple_CancelledFirstCallerRetiresFetch pins that a shared fetch
// never outlives the caller that started it: with no deadline and an HTTP
// client without a timeout, cancelling that caller ends the stalled request,
// and a later caller gets a fresh fetch instead of joining a stranded one.
func TestGetOCSPStaple_CancelledFirstCallerRetiresFetch(t *testing.T) {
	t.Parallel()
	ca := testhelpers.NewCA(t)
	r := newCountingResponder(t, ca, 3*time.Hour)
	cert := chainWith(t, ca, r.srv.URL)

	entered := make(chan struct{})
	var stalled atomic.Bool
	s := NewOCSPStapler(WithHTTPClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if stalled.CompareAndSwap(false, true) {
			close(entered) // the responder stalls on the first request
			<-req.Context().Done()
			return nil, req.Context().Err()
		}
		return http.DefaultTransport.RoundTrip(req)
	})}))

	ctx, cancel := context.WithCancel(t.Context())
	errc := make(chan error, 1)
	go func() {
		_, err := s.GetOCSPStaple(ctx, cert)
		errc <- err
	}()
	<-entered
	cancel()
	require.ErrorIs(t, <-errc, context.Canceled)

	require.Eventually(t, func() bool {
		_, err := s.GetOCSPStaple(t.Context(), cert)
		return err == nil
	}, 5*time.Second, 10*time.Millisecond, "a later caller must not join the stalled fetch forever")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFetch_RetryAndFallbackServers(t *testing.T) {
	t.Parallel()
	ca := testhelpers.NewCA(t)
	down := newCountingResponder(t, ca, 3*time.Hour)
	down.fail.Store(true)
	up := newCountingResponder(t, ca, 3*time.Hour)
	tr := &countingTransport{}

	s := NewOCSPStapler(
		WithHTTPClient(&http.Client{Transport: tr}),
		WithRetryPolicy(&mockRetryPolicy{maxAttempts: 2, nextDelay: time.Millisecond, shouldRetry: true}),
		WithMaxResponseAge(time.Hour),
	)
	staple, err := s.GetOCSPStaple(t.Context(), chainWith(t, ca, down.srv.URL, up.srv.URL))
	require.NoError(t, err)
	require.NotEmpty(t, staple)
	require.GreaterOrEqual(t, down.hits.Load(), int32(2), "the failing server is retried")
	require.Equal(t, int32(1), up.hits.Load())
	require.Equal(t, down.hits.Load()+up.hits.Load(), tr.n.Load(), "the configured HTTP client is used")
}

func TestFetch_Failures(t *testing.T) {
	t.Parallel()
	ca := testhelpers.NewCA(t)
	s := NewOCSPStapler()

	noServer := ca.SignLeaf(t)
	noServer.Certificate = append(noServer.Certificate, ca.Cert.Raw)
	_, err := s.GetOCSPStaple(t.Context(), &noServer)
	require.ErrorContains(t, err, "no OCSP server")

	r := newCountingResponder(t, ca, 3*time.Hour)
	noIssuer := ca.SignLeaf(t, testhelpers.WithOCSPServers(r.srv.URL))
	noIssuer.Leaf = nil
	_, err = s.GetOCSPStaple(t.Context(), &tls.Certificate{Certificate: noIssuer.Certificate[:1]})
	require.ErrorContains(t, err, "issuer certificate not found")

	badIssuer := &tls.Certificate{Certificate: [][]byte{noIssuer.Certificate[0], []byte("junk")}}
	_, err = s.GetOCSPStaple(t.Context(), badIssuer)
	require.Error(t, err)

	_, err = s.GetOCSPStaple(t.Context(), &tls.Certificate{Certificate: [][]byte{[]byte("junk")}})
	require.Error(t, err)

	revoked := newCountingResponder(t, ca, 3*time.Hour)
	revoked.status.Store(int32(xocsp.Revoked))
	_, err = s.GetOCSPStaple(t.Context(), chainWith(t, ca, revoked.srv.URL))
	require.ErrorContains(t, err, "not good")

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = s.GetOCSPStaple(ctx, chainWith(t, ca, r.srv.URL))
	require.ErrorIs(t, err, context.Canceled)
}

func TestFetch_FarNextUpdateIsCapped(t *testing.T) {
	t.Parallel()
	ca := testhelpers.NewCA(t)
	r := newCountingResponder(t, ca, 30*24*time.Hour)
	s := NewOCSPStapler()
	cert := chainWith(t, ca, r.srv.URL)

	_, err := s.GetOCSPStaple(t.Context(), cert)
	require.NoError(t, err)
	s.mu.RLock()
	e := s.cache[cacheKeyOf(cert)]
	s.mu.RUnlock()
	require.WithinDuration(t, time.Now().Add(DefaultOCSPExpiry), e.nextUpdate, time.Minute)
}

func TestStapleCertificate(t *testing.T) {
	t.Parallel()
	ca := testhelpers.NewCA(t)
	r := newCountingResponder(t, ca, 3*time.Hour)
	cert := chainWith(t, ca, r.srv.URL)

	got, err := StapleCertificate(t.Context(), nil, cert)
	require.NoError(t, err)
	require.Same(t, cert, got)

	got, err = StapleCertificate(t.Context(), NewOCSPStapler(), nil)
	require.NoError(t, err)
	require.Nil(t, got)

	got, err = StapleCertificate(t.Context(), NewOCSPStapler(), cert)
	require.NoError(t, err)
	require.NotEmpty(t, got.OCSPStaple)
	require.Empty(t, cert.OCSPStaple, "the input certificate is not mutated")

	r.fail.Store(true)
	_, err = StapleCertificate(t.Context(), NewOCSPStapler(WithFailureMode(FailureModeHard)), chainWith(t, ca, r.srv.URL))
	require.Error(t, err)

	got, err = StapleCertificate(t.Context(), NewOCSPStapler(), cert)
	require.NoError(t, err)
	require.Empty(t, got.OCSPStaple, "soft mode serves the certificate without a staple")
}

func TestFailureMode_ZeroValueStapler(t *testing.T) {
	t.Parallel()
	require.Equal(t, DefaultFailureMode, (&Stapler{}).FailureMode())
}
