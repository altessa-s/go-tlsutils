// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Package tlsletsencrypt provides Let's Encrypt TLS certificate provider using HTTP-01 ACME challenges.
// It manages certificate issuance, renewal, and caching. Call [LetsEncrypt.Close]
// to cancel issuance and renewal and shut down the challenge server.
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
