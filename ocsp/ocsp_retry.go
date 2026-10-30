// Copyright 2021-2026 ALTESSA SOLUTIONS INC. All rights reserved.
// Use of this source code is governed by license that can be found in
// the LICENSE file.

package ocsp

import (
	"context"
	"time"

	coreretry "github.com/altessa-s/go-atlas-core/retry"
)

// RetryPolicy defines the interface for OCSP retry policies.
// Implement this interface to provide custom retry behavior for OCSP requests.
type RetryPolicy interface {
	// NextRetry returns the duration to wait before the next retry.
	// The attempt parameter is the current attempt number starting from 0.
	// Returns 0 to stop retrying.
	NextRetry(attempt int) time.Duration

	// MaxAttempts returns the maximum number of retry attempts.
	// Returns -1 for unlimited retries.
	MaxAttempts() int

	// ShouldRetry determines if the error is retryable.
	ShouldRetry(err error) bool
}

// ExecuteWithRetry runs fn under policy until it succeeds, the policy stops
// retrying, or ctx is done, and returns the last error or nil. A nil policy
// runs fn exactly once. Optional behavior (a [WithOnRetry] callback) is set
// with [RetryOption] values.
//
// Example:
//
//	err := ExecuteWithRetry(ctx, myPolicy, func() error {
//		return doSomething()
//	}, WithOnRetry(logRetry))
func ExecuteWithRetry(ctx context.Context, policy RetryPolicy, fn func() error, opts ...RetryOption) error {
	if policy == nil {
		return fn()
	}
	o := newRetryOptions(opts...)
	return coreretry.Do(ctx, func(context.Context) error {
		return fn()
	},
		coreretry.WithMaxAttempts(policy.MaxAttempts()),
		coreretry.WithShouldRetry(policy.ShouldRetry),
		coreretry.WithNextDelay(func(attempt int, _ error) time.Duration {
			return policy.NextRetry(attempt)
		}),
		coreretry.WithOnRetry(o.onRetry),
	)
}
