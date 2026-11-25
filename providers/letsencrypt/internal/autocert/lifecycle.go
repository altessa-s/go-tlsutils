// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file at the repository root.

package autocert

import (
	"context"
	"errors"
	"sync"
)

// ErrClosed is returned when a closed manager is asked for a certificate.
var ErrClosed = errors.New("letsencrypt: provider is closed")

// lifecycle registers work and prevents new registrations once shutdown starts.
type lifecycle struct {
	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	work   sync.WaitGroup
}

// begin registers an operation. Its caller must call work.Done on success.
func (l *lifecycle) begin() (context.Context, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.done != nil {
		return nil, false
	}

	if l.ctx == nil {
		l.ctx, l.cancel = context.WithCancel(context.Background())
	}

	l.work.Add(1)

	return l.ctx, true
}

func (l *lifecycle) run(f func(context.Context)) bool {
	ctx, ok := l.begin()
	if !ok {
		return false
	}

	go func() {
		defer l.work.Done()

		f(ctx)
	}()

	return true
}

// Stop cancels manager work and returns a channel closed when all registered
// operations have exited and the manager has released its in-memory state.
func (m *Manager) Stop() <-chan struct{} {
	l := &m.lifecycle
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.done == nil {
		l.done = make(chan struct{})
		if l.cancel != nil {
			l.cancel()
		}

		go func() {
			l.work.Wait()

			m.state = nil
			m.renewal = nil
			m.certTokens = nil
			m.httpTokens = nil
			m.client = nil

			close(l.done)
		}()
	}

	return l.done
}
