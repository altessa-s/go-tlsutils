// Copyright 2021-2026 ALTESSA SOLUTIONS INC. All rights reserved.
// Use of this source code is governed by license that can be found in
// the LICENSE file.

package ocsp

import (
	"context"
	"crypto/tls"
	"errors"
	"sync/atomic"

	"github.com/altessa-s/go-atlas-core/collections/slices"
)

// ErrSchedulerManaged is returned by [Stapler.RunRefreshAll] once the refresh
// has been handed to a scheduler and direct invocation is no longer allowed.
var ErrSchedulerManaged = errors.New("ocsp: refresh is managed by a scheduler, direct calls not allowed")

// refreshGuard coordinates the refresh-all cycle that can be driven either by
// a scheduler or by manual calls, but never by both: once registered, manual
// runs fail with [ErrSchedulerManaged], and overlapping runs collapse into one.
// The zero value is ready to use.
type refreshGuard struct {
	registered atomic.Bool
	running    atomic.Bool
}

// tryRun executes fn unless another execution is in flight, in which case it
// returns nil without invoking fn.
func (g *refreshGuard) tryRun(ctx context.Context, fn func(context.Context) error) error {
	if !g.running.CompareAndSwap(false, true) {
		return nil // Already running, skip this cycle.
	}
	defer g.running.Store(false)
	return fn(ctx)
}

// RefreshAllFunc returns the refresh-all cycle wrapped with the single-flight
// guard, for registration with a scheduler. Unlike
// [Stapler.RegisterRefreshAllSchedulerFunc] it does not mark the refresh as
// scheduler-managed: call [Stapler.MarkSchedulerManaged] once the scheduler
// has accepted the task, so a rejected registration leaves
// [Stapler.RunRefreshAll] usable as the fallback driver.
func (s *Stapler) RefreshAllFunc() func(context.Context) error {
	return func(ctx context.Context) error {
		return s.refreshAllTask.tryRun(ctx, s.runRefreshAllInternal)
	}
}

// MarkSchedulerManaged marks the refresh as scheduler-managed. After it,
// [Stapler.RunRefreshAll] returns [ErrSchedulerManaged].
func (s *Stapler) MarkSchedulerManaged() {
	s.refreshAllTask.registered.Store(true)
}

// RegisterRefreshAllSchedulerFunc returns a function for use by a scheduler and marks
// refresh as scheduler-managed. After calling this method, direct calls to
// RunRefreshAll will return [ErrSchedulerManaged].
func (s *Stapler) RegisterRefreshAllSchedulerFunc() func(context.Context) error {
	s.MarkSchedulerManaged()
	return s.RefreshAllFunc()
}

// RunRefreshAll refreshes all OCSP responses in the cache that need it.
// This method is designed to be called manually for one-time refresh.
// If the function is registered with a scheduler, this method returns
// [ErrSchedulerManaged].
func (s *Stapler) RunRefreshAll(ctx context.Context) error {
	if s.refreshAllTask.registered.Load() {
		return ErrSchedulerManaged
	}
	return s.refreshAllTask.tryRun(ctx, s.runRefreshAllInternal)
}

// runRefreshAllInternal performs the actual refresh of all OCSP responses.
// Callers must route through refreshAllTask so overlapping cycles collapse
// into a single execution.
func (s *Stapler) runRefreshAllInternal(ctx context.Context) error {
	s.mu.RLock()
	// Collect all entries to avoid holding the lock while fetching
	type refreshItem struct {
		cert *tls.Certificate
	}
	var items []refreshItem
	for _, entry := range s.cache {
		items = slices.AppendIf(items, entry.cert != nil, refreshItem{cert: entry.cert})
	}
	s.mu.RUnlock()

	var errs []error
	for _, item := range items {
		errs = slices.AppendNonNil(errs, s.RunRefreshCycle(ctx, item.cert))
	}

	return errors.Join(errs...)
}
