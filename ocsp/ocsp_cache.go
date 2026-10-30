// Copyright 2021-2026 ALTESSA SOLUTIONS INC. All rights reserved.
// Use of this source code is governed by license that can be found in
// the LICENSE file.

package ocsp

import (
	"crypto/tls"
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

// evictOldestLocked removes the cache entry with the earliest nextUpdate.
// Caller must hold s.mu in write mode. Returns true when an entry was
// removed, false when the cache is already empty.
func (s *Stapler) evictOldestLocked() bool {
	var (
		oldestKey  string
		oldestTime time.Time
		first      = true
	)
	for key, entry := range s.cache {
		entry.mu.RLock()
		t := entry.nextUpdate
		entry.mu.RUnlock()
		if first || t.Before(oldestTime) {
			oldestKey = key
			oldestTime = t
			first = false
		}
	}
	if first {
		return false
	}
	delete(s.cache, oldestKey)
	return true
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
