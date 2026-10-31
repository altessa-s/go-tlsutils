// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Package integration holds cross-package, in-process end-to-end tests for
// go-tlsutils. The tests wire real components together — certificate
// providers, the OCSP stapler, an OCSP responder built on
// golang.org/x/crypto/ocsp, and the client helpers of the root package — and
// drive real TLS handshakes over net.Pipe or loopback listeners.
//
// # Running
//
// The tests are guarded by the integration build tag, so a plain go test run
// compiles this package without executing anything:
//
//	go test -tags integration ./integration/...
//
// They need no Docker and no network beyond loopback.
package integration
