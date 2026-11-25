// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package autocert

import (
	"context"
	"crypto"
	"time"
)

const (
	renewalTimeout       = 10 * time.Minute
	minRenewalRetryDelay = 30 * time.Minute
	maxRenewBefore       = 30 * 24 * time.Hour
	renewBeforeDivisor   = 3
	renewalJitterDivisor = 10
)

// domainRenewal tracks the state used by the periodic timers
// renewing a single domain's cert.
type domainRenewal struct {
	m   *Manager
	ck  certKey
	key crypto.Signer
}

// run renews one certificate until the manager closes.
func (dr *domainRenewal) run(ctx context.Context, notBefore, notAfter time.Time) {
	timer := time.NewTimer(dr.next(notBefore, notAfter))
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if ctx.Err() != nil {
				return
			}
		}

		renewCtx, cancel := context.WithTimeout(ctx, renewalTimeout)
		next, err := dr.do(renewCtx)

		cancel()

		if err != nil {
			next = minRenewalRetryDelay
			next += time.Duration(pseudoRand.int63n(int64(next)))
		}

		timer.Reset(next)
	}
}

// updateState locks and replaces the relevant Manager.state item with the given
// state. It additionally updates dr.key with the given state's key.
func (dr *domainRenewal) updateState(state *certState) {
	dr.m.stateMu.Lock()
	defer dr.m.stateMu.Unlock()

	dr.key = state.key
	dr.m.state[dr.ck] = state
}

// do is similar to Manager.createCert but it doesn't lock a Manager.state item.
// Instead, it requests a new certificate independently and, upon success,
// replaces dr.m.state item with a new one and updates cache for the given domain.
//
// It may lock and update the Manager.state if the expiration date of the currently
// cached cert is far enough in the future.
//
// The returned value is a time interval after which the renewal should occur again.
func (dr *domainRenewal) do(ctx context.Context) (time.Duration, error) {
	// a race is likely unavoidable in a distributed environment
	// but we try nonetheless
	if tlscert, err := dr.m.cacheGet(ctx, dr.ck); err == nil {
		next := dr.next(tlscert.Leaf.NotBefore, tlscert.Leaf.NotAfter)
		if next > 0 {
			signer, ok := tlscert.PrivateKey.(crypto.Signer)
			if ok {
				state := &certState{
					key:  signer,
					cert: tlscert.Certificate,
					leaf: tlscert.Leaf,
				}
				dr.updateState(state)

				return next, nil
			}
		}
	}

	der, leaf, err := dr.m.authorizedCert(ctx, dr.key, dr.ck)
	if err != nil {
		return 0, err
	}

	state := &certState{
		key:  dr.key,
		cert: der,
		leaf: leaf,
	}

	tlscert, err := state.tlscert()
	if err != nil {
		return 0, err
	}

	if err := dr.m.cachePut(ctx, dr.ck, tlscert); err != nil {
		return 0, err
	}

	dr.updateState(state)

	return dr.next(leaf.NotBefore, leaf.NotAfter), nil
}

// next returns the wait time before the next renewal should start.
// If manager.RenewBefore is set, it uses that capped at 30 days,
// otherwise it uses a default of 1/3 of the cert lifetime.
// It builds in a jitter of 10% of the renew threshold, capped at 1 hour.
func (dr *domainRenewal) next(notBefore, notAfter time.Time) time.Duration {
	threshold := min(notAfter.Sub(notBefore)/renewBeforeDivisor, maxRenewBefore)
	if dr.m.RenewBefore > 0 {
		threshold = min(dr.m.RenewBefore, maxRenewBefore)
	}

	maxJitter := min(threshold/renewalJitterDivisor, time.Hour)

	var jitter time.Duration
	if maxJitter > 0 {
		jitter = time.Duration(pseudoRand.int63n(int64(maxJitter)))
	}

	renewAt := notAfter.Add(-(threshold - jitter))

	return max(0, time.Until(renewAt))
}
