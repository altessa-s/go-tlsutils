// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package ocsp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-tlsutils/internal/testhelpers"
)

// TestNewOCSPStapler_FallsBackWhenOptionsClearDefaults pins NewOCSPStapler's
// own defensive defaulting: even though newOptions always fills in a logger
// and failure mode today, a hand-written Option can still hand it a cleared
// options struct. A future change to the generated defaults must not leave
// the Stapler with a nil logger or an empty failure mode.
func TestNewOCSPStapler_FallsBackWhenOptionsClearDefaults(t *testing.T) {
	t.Parallel()

	clearDefaults := func(o *options) {
		o.logger = nil
		o.failureMode = ""
	}

	s := NewOCSPStapler(clearDefaults)
	require.NotNil(t, s.logger, "NewOCSPStapler must guarantee a non-nil logger")
	require.Equal(t, DefaultFailureMode, s.failureMode, "NewOCSPStapler must guarantee a failure mode")
}

// TestGetOCSPStaple_PeriodicCleanupTriggersOnInterval pins the lazy-cleanup
// trigger: the call whose counter lands on defaultCleanupInterval must sweep
// expired entries out of the cache, not just the certificate it is fetching.
func TestGetOCSPStaple_PeriodicCleanupTriggersOnInterval(t *testing.T) {
	t.Parallel()
	ca := testhelpers.NewCA(t)
	r := newCountingResponder(t, ca, 3*time.Hour)
	cert := chainWith(t, ca, r.srv.URL)
	s := NewOCSPStapler()

	s.mu.Lock()
	s.cache["stale"] = &ocspCacheEntry{nextUpdate: time.Now().Add(-time.Hour)}
	s.mu.Unlock()
	s.cleanupCounter.Store(defaultCleanupInterval - 1)

	_, err := s.GetOCSPStaple(t.Context(), cert)
	require.NoError(t, err)

	s.mu.RLock()
	_, stillStale := s.cache["stale"]
	s.mu.RUnlock()
	require.False(t, stillStale, "the Nth GetOCSPStaple call must run the lazy cleanup pass")
}

// TestGetOCSPStaple_CacheHitSkipsRefetch pins cachedResponse's valid-entry
// path reached from GetOCSPStaple's own cache check: a second call for the
// same certificate must be served from cache, without another fetch.
func TestGetOCSPStaple_CacheHitSkipsRefetch(t *testing.T) {
	t.Parallel()
	ca := testhelpers.NewCA(t)
	r := newCountingResponder(t, ca, 3*time.Hour)
	cert := chainWith(t, ca, r.srv.URL)
	s := NewOCSPStapler()

	first, err := s.GetOCSPStaple(t.Context(), cert)
	require.NoError(t, err)
	require.Equal(t, int32(1), r.hits.Load())

	second, err := s.GetOCSPStaple(t.Context(), cert)
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Equal(t, int32(1), r.hits.Load(), "a cached, still-valid response must not trigger a refetch")
}

// TestGetOCSPStaple_ExpiredCacheEntryTriggersRefetch pins cachedResponse's
// expired-entry path: an entry whose nextUpdate has passed must be treated
// as a miss, not served stale, so GetOCSPStaple fetches a fresh response.
func TestGetOCSPStaple_ExpiredCacheEntryTriggersRefetch(t *testing.T) {
	t.Parallel()
	ca := testhelpers.NewCA(t)
	r := newCountingResponder(t, ca, 3*time.Hour)
	cert := chainWith(t, ca, r.srv.URL)
	s := NewOCSPStapler()

	s.mu.Lock()
	s.cache[cacheKey(cert)] = &ocspCacheEntry{response: []byte("stale"), nextUpdate: time.Now().Add(-time.Minute)}
	s.mu.Unlock()

	staple, err := s.GetOCSPStaple(t.Context(), cert)
	require.NoError(t, err)
	require.NotEqual(t, []byte("stale"), staple)
	require.Equal(t, int32(1), r.hits.Load(), "an expired cache entry must be treated as a miss and refetched")
}
