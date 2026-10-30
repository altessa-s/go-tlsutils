// Copyright 2021-2026 ALTESSA SOLUTIONS INC. All rights reserved.
// Use of this source code is governed by license that can be found in
// the LICENSE file.

package ocsp

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type mockRetryPolicy struct {
	maxAttempts int
	nextDelay   time.Duration
	shouldRetry bool
}

func (m *mockRetryPolicy) NextRetry(_ int) time.Duration { return m.nextDelay }
func (m *mockRetryPolicy) MaxAttempts() int              { return m.maxAttempts }
func (m *mockRetryPolicy) ShouldRetry(_ error) bool      { return m.shouldRetry }

func TestExecuteWithRetry_NilPolicy(t *testing.T) {
	t.Parallel()
	calls := 0
	err := ExecuteWithRetry(t.Context(), nil, func() error {
		calls++
		return errors.New("fails once")
	})
	require.Error(t, err)
	require.Equal(t, 1, calls, "a nil policy runs fn exactly once")
}

func TestExecuteWithRetry_Success(t *testing.T) {
	t.Parallel()
	policy := &mockRetryPolicy{maxAttempts: 3, nextDelay: time.Millisecond, shouldRetry: true}
	err := ExecuteWithRetry(t.Context(), policy, func() error {
		return nil
	})
	require.NoError(t, err)
}

func TestExecuteWithRetry_PermanentError(t *testing.T) {
	t.Parallel()
	testErr := errors.New("permanent error")
	policy := &mockRetryPolicy{maxAttempts: 3, nextDelay: time.Millisecond, shouldRetry: false}
	calls := 0
	err := ExecuteWithRetry(t.Context(), policy, func() error {
		calls++
		return testErr
	})
	require.ErrorIs(t, err, testErr)
	require.Equal(t, 1, calls)
}

func TestExecuteWithRetry_WithOnRetry(t *testing.T) {
	t.Parallel()
	attempts := 0
	policy := &mockRetryPolicy{maxAttempts: 2, nextDelay: time.Millisecond, shouldRetry: true}

	retryCount := 0
	_ = ExecuteWithRetry(t.Context(), policy, func() error {
		attempts++
		return errors.New("transient")
	}, WithOnRetry(func(int, error, time.Duration) {
		retryCount++
	}))

	require.Equal(t, 3, attempts, "MaxAttempts counts retries after the first attempt")
	require.Equal(t, 2, retryCount, "OnRetry runs before each retry, not before the first attempt")
}
