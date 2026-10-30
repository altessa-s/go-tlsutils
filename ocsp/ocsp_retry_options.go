// Copyright 2021-2026 ALTESSA SOLUTIONS INC. All rights reserved.
// Use of this source code is governed by license that can be found in
// the LICENSE file.

package ocsp

//go:generate optgen generate --type=retryOptions --option-type=RetryOption --output=ocsp_retry_options_gen.go

import coreretry "github.com/altessa-s/go-atlas-core/retry"

// retryOptions configures [ExecuteWithRetry]. All fields are populated by
// generated [RetryOption] setters in ocsp_retry_options_gen.go.
type retryOptions struct {
	// onRetry is invoked before each retry attempt with the zero-based
	// attempt that failed, its error, and the delay before the next one.
	// Nil disables it.
	onRetry coreretry.OnRetryFunc
}
