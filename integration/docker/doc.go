// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Package docker holds the Docker-backed integration tests for go-tlsutils.
//
// The tests run the certificate providers against real backends started with
// testcontainers-go and complete a TLS handshake verified against the
// backend's CA. They live in a nested module so testcontainers never enters
// the library's go.mod, and they are guarded by the integration_docker build
// tag so a plain go test skips them. Every test skips when no Docker provider
// is available.
//
// # Scenarios
//
//   - Vault dev server: providers/vault issues a certificate from a PKI mount.
//   - MinIO: providers/s3 loads a leaf and chain, then reloads after an overwrite.
//   - Pebble: providers/letsencrypt obtains a certificate from an ACME test server.
//
// # Running
//
//	go -C integration/docker test -tags integration_docker ./...
package docker
