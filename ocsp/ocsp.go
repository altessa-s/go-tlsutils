// Copyright 2021-2026 ALTESSA SOLUTIONS INC. All rights reserved.
// Use of this source code is governed by license that can be found in
// the LICENSE file.

package ocsp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	coreerrs "github.com/altessa-s/go-atlas-core/errors"
	tlsutils "github.com/altessa-s/go-tlsutils"
)

const (
	// DefaultHTTPTimeout is the default HTTP client timeout for OCSP requests.
	DefaultHTTPTimeout = 10 * time.Second
	// DefaultOCSPExpiry is the default expiry time for OCSP responses when NextUpdate is not set.
	DefaultOCSPExpiry = 24 * time.Hour
	// defaultCleanupInterval determines how often lazy cleanup runs (every N GetOCSPStaple calls).
	defaultCleanupInterval = 100
	// handshakeOCSPTimeout is the maximum time for OCSP operations during TLS handshake.
	handshakeOCSPTimeout = 5 * time.Second
	// refreshBuffer is the time before nextUpdate when refresh is considered needed.
	// OCSP responses are refreshed when less than this duration remains until expiration.
	refreshBuffer = time.Hour
	// maxOCSPResponseSize caps how many bytes are read from an OCSP responder
	// (including after transparent gzip decompression). DER-encoded OCSP responses are a few KB;
	// 1 MiB is far above any legitimate response.
	maxOCSPResponseSize = 1 << 20 // 1 MiB
	// ocspClockSkew is the tolerance applied to a response's thisUpdate and
	// nextUpdate when checking that it is currently valid.
	ocspClockSkew = 5 * time.Minute
)

// ErrStaleResponse indicates an OCSP response outside its validity window: its
// nextUpdate has passed, its thisUpdate is in the future, or — when it carries
// no nextUpdate — its thisUpdate is older than the maximum response age (see
// [WithMaxResponseAge]).
var ErrStaleResponse = errors.New("ocsp: response is not within its validity window")

var _ tlsutils.OCSPStapler = (*Stapler)(nil)

// Stapler manages OCSP stapling for TLS certificates.
// It provides automatic caching and refresh of OCSP responses.
// All methods are safe for concurrent use.
//
// Periodic refresh is the caller's job. Register [Stapler.RefreshAllFunc] with
// an external scheduler, then call [Stapler.MarkSchedulerManaged] only after
// that registration succeeds. A rejected registration leaves
// [Stapler.RunRefreshAll] available.
//
//	fn := stapler.RefreshAllFunc()
//	if err := register(ctx, fn); err != nil {
//	    // RunRefreshAll stays available.
//	} else {
//	    stapler.MarkSchedulerManaged()
//	}
//
// Expired cache entries are cleaned up lazily during GetOCSPStaple calls.
type Stapler struct {
	mu             sync.RWMutex
	cache          map[string]*ocspCacheEntry
	httpClient     *http.Client
	retryPolicy    RetryPolicy
	logger         *slog.Logger
	cleanupCounter atomic.Uint64 // atomic counter for lazy cleanup
	refreshAllTask refreshGuard  // Guards RunRefreshAll and marks scheduler management.

	enableCompression bool
	// failureMode controls handshake behavior when GetOCSPStaple cannot
	// produce a valid response — see [FailureMode] for the rationale.
	failureMode FailureMode
	// maxCacheEntries bounds the OCSP response cache. When zero, the
	// cache is unbounded (legacy behavior; opt-out for callers who
	// know their cert population is small and want to skip eviction
	// bookkeeping).
	maxCacheEntries int
	// maxResponseAge bounds the age of a response without a nextUpdate.
	maxResponseAge time.Duration
}

// FailureMode returns the configured [FailureMode]. [StapleOCSPToConfig]
// uses this to decide whether a failed staple-fetch should be served
// as a cert-without-staple (Soft) or rejected (Hard).
func (s *Stapler) FailureMode() FailureMode {
	if s.failureMode == "" {
		return DefaultFailureMode
	}
	return s.failureMode
}

// NewOCSPStapler creates a new OCSP stapler with the specified options.
// By default, compression is disabled and no retry policy is configured.
//
// Example:
//
//	stapler := ocsp.NewOCSPStapler(
//	    ocsp.WithCompression(),
//	    ocsp.WithLogger(slog.Default()),
//	)
func NewOCSPStapler(opts ...Option) *Stapler {
	o := newOptions(opts...)

	httpClient := o.httpClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultHTTPTimeout}
	}

	// Ensure logger is never nil
	logger := o.logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	failureMode := o.failureMode
	if failureMode == "" {
		failureMode = DefaultFailureMode
	}

	s := &Stapler{
		cache:             make(map[string]*ocspCacheEntry),
		httpClient:        httpClient,
		retryPolicy:       o.retryPolicy,
		logger:            logger,
		enableCompression: o.enableCompression,
		failureMode:       failureMode,
		maxCacheEntries:   o.maxCacheEntries,
		maxResponseAge:    o.maxResponseAge,
	}

	return s
}

// GetOCSPStaple returns the OCSP staple for the given certificate.
// It checks the cache first and fetches a new response if necessary.
// The context controls the HTTP request timeout and cancellation.
//
// Example:
//
//	staple, err := stapler.GetOCSPStaple(ctx, &cert)
//	if err == nil {
//		cert.OCSPStaple = staple
//	}
func (s *Stapler) GetOCSPStaple(ctx context.Context, cert *tls.Certificate) ([]byte, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, errors.New("invalid certificate")
	}

	// Lazy cleanup of expired entries every N calls
	if s.cleanupCounter.Add(1)%defaultCleanupInterval == 0 {
		s.removeExpiredEntries()
	}

	// Parse the certificate if not already parsed
	var leafCert *x509.Certificate
	if cert.Leaf != nil {
		leafCert = cert.Leaf
	} else {
		var err error
		leafCert, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, coreerrs.WrapOperation(err, "parse certificate")
		}
	}

	cacheKey := base64.StdEncoding.EncodeToString(cert.Certificate[0])

	s.mu.RLock()
	entry, exists := s.cache[cacheKey]
	s.mu.RUnlock()

	if exists {
		// Snapshot the entry under a read lock, then release it immediately so
		// the read lock is not held across the network fetch below (which would
		// serialize RunRefreshCycle behind handshake traffic).
		entry.mu.RLock()
		valid := time.Now().Before(entry.nextUpdate)
		response := entry.response
		entry.mu.RUnlock()

		// Return cached response if still valid
		if valid {
			return response, nil
		}
	}

	// Fetch new OCSP response
	response, nextUpdate, err := s.fetchOCSPResponse(ctx, cert, leafCert)
	if err != nil {
		return nil, err
	}

	cacheEntry := &ocspCacheEntry{response: response, nextUpdate: nextUpdate}

	s.mu.Lock()
	// Enforce the cap before inserting. evictOldestLocked picks the
	// entry whose nextUpdate is closest to "now" — expired entries go
	// first, then the soonest-to-expire — so the eviction does
	// minimum damage to the cache's hit rate.
	if s.maxCacheEntries > 0 {
		for len(s.cache) >= s.maxCacheEntries {
			if !s.evictOldestLocked() {
				break // pathological: no entries available to evict
			}
		}
	}
	s.cache[cacheKey] = cacheEntry
	cacheEntry.cert = cert
	s.mu.Unlock()

	return response, nil
}

// NeedsRefresh returns true if the certificate's OCSP response needs refreshing.
// A response needs refresh if:
//   - It doesn't exist in the cache
//   - It will expire within the configured refresh period
//
// This method is useful for determining whether to call RunRefreshCycle.
//
// Example:
//
//	if stapler.NeedsRefresh(cert) {
//	    if err := stapler.RunRefreshCycle(ctx, cert); err != nil {
//	        log.Printf("OCSP refresh failed: %v", err)
//	    }
//	}
func (s *Stapler) NeedsRefresh(cert *tls.Certificate) bool {
	if cert == nil || len(cert.Certificate) == 0 {
		return false
	}

	cacheKey := base64.StdEncoding.EncodeToString(cert.Certificate[0])

	s.mu.RLock()
	entry, exists := s.cache[cacheKey]
	s.mu.RUnlock()

	if !exists {
		return true
	}

	entry.mu.RLock()
	needsRefresh := time.Now().Add(refreshBuffer).After(entry.nextUpdate)
	entry.mu.RUnlock()

	return needsRefresh
}

// RunRefreshCycle checks and refreshes the OCSP response for a certificate if needed.
// This method is designed to be called periodically via an external scheduler.
//
// The method:
//   - Checks if the cached response exists and is approaching expiration
//   - Fetches a new OCSP response if needed
//   - Updates the cache with the new response
//
// To refresh every cached certificate on a schedule, register
// [Stapler.RefreshAllFunc] with the caller's scheduler and call
// [Stapler.MarkSchedulerManaged] only after that registration succeeds.
//
// Returns nil if the response is still valid and doesn't need refresh,
// or if the refresh was successful. Returns an error if the refresh fails.
func (s *Stapler) RunRefreshCycle(ctx context.Context, cert *tls.Certificate) error {
	if cert == nil || len(cert.Certificate) == 0 {
		return errors.New("invalid certificate")
	}

	cacheKey := base64.StdEncoding.EncodeToString(cert.Certificate[0])

	// Check if refresh is needed
	s.mu.RLock()
	entry, exists := s.cache[cacheKey]
	s.mu.RUnlock()

	// If no cache entry exists, fetch and cache
	if !exists {
		_, err := s.GetOCSPStaple(ctx, cert)
		return err
	}

	// Check if refresh is needed based on expiration time
	entry.mu.RLock()
	needsRefresh := time.Now().Add(refreshBuffer).After(entry.nextUpdate)
	entry.mu.RUnlock()

	if !needsRefresh {
		s.logger.DebugContext(ctx, "OCSP response still valid, skipping refresh")
		return nil
	}

	// Parse the certificate
	leafCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return coreerrs.WrapOperation(err, "parse certificate for refresh")
	}

	// Fetch new response
	response, nextUpdate, err := s.fetchOCSPResponse(ctx, cert, leafCert)
	if err != nil {
		s.logger.WarnContext(ctx, "failed to refresh OCSP response", slog.Any("error", err))
		return err
	}

	entry.mu.Lock()
	entry.response = response
	entry.nextUpdate = nextUpdate
	entry.mu.Unlock()

	s.logger.DebugContext(ctx, "OCSP response refreshed successfully",
		slog.Time("next_update", nextUpdate))

	return nil
}
