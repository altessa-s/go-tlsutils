// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package ocsp

import (
	"crypto/tls"
	"encoding/base64"
	"sync"
	"time"
)

// ocspCacheEntry holds the raw DER response. It is not compressed: signed DER
// OCSP responses are effectively incompressible, so gzip would save no memory
// while costing a decode on every handshake.
type ocspCacheEntry struct {
	response   []byte
	nextUpdate time.Time
	cert       *tls.Certificate
	mu         sync.RWMutex
}

// cacheKey identifies the cache entry of cert by its leaf certificate.
func cacheKey(cert *tls.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Certificate[0])
}

// store inserts entry under key, first making room when the cache is at
// its cap and key is new.
func (s *Stapler) store(key string, entry *ocspCacheEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.cache[key]; !exists && s.maxCacheEntries > 0 && len(s.cache) >= s.maxCacheEntries {
		s.makeRoomLocked(time.Now())
	}
	s.cache[key] = entry
}

// makeRoomLocked frees at least one slot in a full cache with a single scan:
// every expired entry is dropped, and when that leaves the cache full, the
// entry closest to expiry is evicted. Dropping all expired entries at once
// keeps the following inserts from scanning again. Caller must hold s.mu in
// write mode.
func (s *Stapler) makeRoomLocked(now time.Time) {
	var (
		oldestKey  string
		oldestTime time.Time
		found      bool
	)
	for key, entry := range s.cache {
		entry.mu.RLock()
		t := entry.nextUpdate
		entry.mu.RUnlock()
		if now.After(t) {
			delete(s.cache, key)
			continue
		}
		if !found || t.Before(oldestTime) {
			oldestKey, oldestTime, found = key, t, true
		}
	}
	if found && len(s.cache) >= s.maxCacheEntries {
		delete(s.cache, oldestKey)
	}
}

// removeExpiredEntries removes all expired cache entries.
func (s *Stapler) removeExpiredEntries() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for key, entry := range s.cache {
		entry.mu.RLock()
		expired := now.After(entry.nextUpdate)
		entry.mu.RUnlock()

		if expired {
			delete(s.cache, key)
		}
	}
}
