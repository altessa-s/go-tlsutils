// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Package ocsp provides OCSP stapling for TLS certificates with caching.
//
// OCSP (Online Certificate Status Protocol) stapling improves TLS handshake performance
// by including certificate revocation status in the TLS handshake, so clients
// don't have to contact the CA directly.
//
// # Features
//
//   - Automatic caching of OCSP responses with lazy expiration cleanup
//   - Whole-cache refresh through [Stapler.RefreshAllFunc], for the caller's scheduler
//   - Response validation: issuer signature, leaf serial number, good status, and
//     validity window (thisUpdate/nextUpdate with clock-skew tolerance; a
//     response without nextUpdate expires DefaultMaxResponseAge after thisUpdate,
//     see WithMaxResponseAge)
//   - StapleOCSPToConfig enforces the failure mode with and without SNI: it moves
//     Config.Certificates into the wrapped GetCertificate
//   - Optional gzip transfer encoding for responder replies (WithCompression)
//   - Configurable retry policies for network failures
//   - Thread-safe concurrent operations
//   - Structured logging support
//
// # Basic Usage
//
//	stapler := ocsp.NewOCSPStapler(
//	    ocsp.WithCompression(),
//	    ocsp.WithLogger(slog.Default()),
//	)
//
//	// Apply to TLS config
//	config := &tls.Config{Certificates: []tls.Certificate{cert}}
//	ocsp.StapleOCSPToConfig(config, stapler)
//
// # Periodic Refresh
//
// The stapler does not run a timer. Register [Stapler.RefreshAllFunc] with the
// caller's scheduler, and call [Stapler.MarkSchedulerManaged] only after that
// registration succeeds. A rejected registration leaves [Stapler.RunRefreshAll]
// usable. [Stapler.RegisterRefreshAllSchedulerFunc] marks the refresh managed
// before the scheduler accepts the task; call it only when registration cannot
// fail.
//
//	fn := stapler.RefreshAllFunc()
//	if err := register(ctx, fn); err != nil {
//	    // RunRefreshAll stays available.
//	} else {
//	    stapler.MarkSchedulerManaged()
//	}
//
// # Manual Refresh
//
//	// Check if refresh is needed
//	if stapler.NeedsRefresh(cert) {
//	    if err := stapler.RunRefreshCycle(ctx, cert); err != nil {
//	        log.Printf("OCSP refresh failed: %v", err)
//	    }
//	}
//
// # Lifecycle Management
//
// The package uses context-based lifecycle management. Each operation accepts a context
// that controls cancellation and timeout. For periodic refresh of the whole cache,
// register [Stapler.RefreshAllFunc] with an external scheduler and call
// [Stapler.MarkSchedulerManaged] only after it accepts the task.
package ocsp
