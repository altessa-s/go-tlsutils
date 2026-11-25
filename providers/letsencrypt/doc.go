// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Package tlsletsencrypt provides Let's Encrypt TLS certificate provider using HTTP-01 ACME challenges.
// It manages certificate issuance, renewal, and caching. Call [LetsEncrypt.Close]
// to shut down the provider's HTTP challenge server and wait for its goroutines.
// The upstream autocert API has no way to stop its internal renewal timer once
// started. The timer continues running until process exit.
//
// Example:
//
//	provider, _ := tlsletsencrypt.New(
//		tlsletsencrypt.WithDomains("example.com"),
//		tlsletsencrypt.WithEmail("admin@example.com"),
//	)
//	defer provider.Close(context.Background())
//	go provider.StartHTTPServer(":80", nil)
//	tlsConfig, _ := provider.TLSConfig()
package tlsletsencrypt
