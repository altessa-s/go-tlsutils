// Copyright 2021-2026 ALTESSA SOLUTIONS INC. All rights reserved.
// Use of this source code is governed by license that can be found in
// the LICENSE file.

// Package certconfig holds the reload steps shared by the TLS providers that
// load a certificate and republish it on change (file, S3): [Build] turns the
// loaded certificate into the server config to publish, with OCSP stapling
// installed before publication, and [Notify] signals a reload without
// blocking.
//
//	cfg := certconfig.Build(ctx, cert, stapler, logger)
//	mu.Lock()
//	published = cfg
//	mu.Unlock()
//	certconfig.Notify(reloadCh)
package certconfig
