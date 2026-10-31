# go-tlsutils

[![CI](https://github.com/altessa-s/go-tlsutils/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/altessa-s/go-tlsutils/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/altessa-s/go-tlsutils.svg)](https://pkg.go.dev/github.com/altessa-s/go-tlsutils)
[![Go Report Card](https://goreportcard.com/badge/github.com/altessa-s/go-tlsutils)](https://goreportcard.com/report/github.com/altessa-s/go-tlsutils)
[![Release](https://img.shields.io/github/v/release/altessa-s/go-tlsutils)](https://github.com/altessa-s/go-tlsutils/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/altessa-s/go-tlsutils)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

```go
import "github.com/altessa-s/go-tlsutils"
```

TLS certificate loading, OCSP stapling, certificate providers and SPIFFE Workload API helpers for Go services and libraries. Sources include files, S3,
Vault PKI and Let's Encrypt. Keys are PKCS#8, PKCS#1 or SEC1. Server and client defaults are TLS 1.2+.

Packages read no configuration schema and report no metrics: callers configure them through options, and mapping configuration onto those options is
left to the caller. OCSP refresh scheduling is the caller's job too. Register `ocsp.Stapler.RefreshAllFunc` and call `MarkSchedulerManaged` only after
the scheduler accepts the task.

## Requirements

Go 1.27 or later (`go 1.27.0` in `go.mod`).

## Packages

| Package                                          | Description                                      |
|--------------------------------------------------|--------------------------------------------------|
| [tlsutils](./)                                   | Certificate loading and TLS 1.2+ defaults        |
| [ocsp](./ocsp)                                   | OCSP stapling with caching and refresh           |
| [providers](./providers)                         | Certificate provider port                        |
| [providers/file](./providers/file)               | File-based certificate loading                   |
| [providers/letsencrypt](./providers/letsencrypt) | Let's Encrypt ACME certificates                  |
| [providers/s3](./providers/s3)                   | S3-backed certificate loading                    |
| [providers/vault](./providers/vault)             | Vault PKI engine certificates                    |
| [spiffe](./spiffe)                               | Rotating mTLS configs from the SPIFFE Workload API |

## Modules

`providers/s3`, `providers/vault` and `spiffe` are separate Go modules, so importing the root module never pulls in (or raises the version of) the AWS
SDK, the Vault client, go-spiffe or gRPC. The import paths are unchanged; require each provider module you use alongside the root:

```sh
go get github.com/altessa-s/go-tlsutils                  # tlsutils, ocsp, providers, providers/file, providers/letsencrypt
go get github.com/altessa-s/go-tlsutils/providers/s3     # S3 provider
go get github.com/altessa-s/go-tlsutils/providers/vault  # Vault PKI provider
go get github.com/altessa-s/go-tlsutils/spiffe           # SPIFFE Workload API
```

Each module is tagged separately (`v0.x.y` for the root, `providers/s3/v0.x.y`, `providers/vault/v0.x.y`, `spiffe/v0.x.y`).

## Functions

| Function                           | Description                              |
|------------------------------------|------------------------------------------|
| `LoadFromFile`                     | Load cert + key from separate files      |
| `LoadFromConcatenatedFile`         | Load cert + key from a single PEM file   |
| `LoadFromBytes`                    | Load cert + key from PEM bytes           |
| `ApplyMinTLSVersion`               | Apply a YAML `minVersion` (`1.2`/`1.3`) to a server `tls.Config`; TLS 1.3 clears the 1.2 cipher list |
| `ResolveMinTLSVersion`             | Parse a `minVersion` string; `ok=false` for unknown input |
| `DefaultTLSConfig`                 | Secure TLS 1.2+ server configuration     |
| `DefaultTLSConfigStrict`           | TLS 1.3-only server configuration        |
| `DefaultClientTLSConfig`           | Secure TLS 1.2+ client configuration     |
| `DefaultClientTLSConfigStrict`     | TLS 1.3-only client configuration        |
| `ClientTLSConfig`                  | Strict client mTLS config presenting a cert from a provider |
| `DialContext`                      | Dial a peer over mutual TLS using a client-cert provider |
| `BuildCAPool`                      | Build certificate pool from CA files     |
| `CloneCertificateWithOCSPStaple`   | Attach OCSP staple to certificate        |

## Design principles

- **Minimal dependencies** — the root module needs the Go standard library, [go-atlas-core](https://github.com/altessa-s/go-atlas-core),
  `youmark/pkcs8` (encrypted PKCS#8 keys), `golang.org/x/crypto` (`ocsp`, `acme`/`autocert` for Let's Encrypt) and `fsnotify` (file provider).
  The heavy SDKs live in their own modules: `aws-sdk-go-v2` (`providers/s3`), `hashicorp/vault/api`, `johanbrandhorst/certify` and
  [go-atlas-net](https://github.com/altessa-s/go-atlas-net) (`providers/vault`), `spiffe/go-spiffe/v2` and `google.golang.org/grpc` (`spiffe`).
- **No metrics, health or config schemas.** Packages are configured through options; configuration mapping and telemetry belong to the caller.
- **SDKs stay inside the provider that needs them.** The root package, `ocsp` and `providers` do not import AWS, Vault, ACME or SPIFFE.
- **Safe by default** — `DefaultTLSConfig` is TLS 1.2+; the OCSP failure mode defaults to soft and hard mode is opt-in.
- **Thread-safe by default** — exported functions and types are safe for concurrent use unless documented otherwise.

## Development

| Command         | Description                                          |
|-----------------|------------------------------------------------------|
| `make test`     | Run all tests                                        |
| `make lint`     | golangci-lint with the repo config (`.golangci.yml`) |
| `make generate` | Install `optgen` and run go generate                 |
| `make bench`    | Run all benchmarks                                   |

`make generate` installs [`optgen`](https://github.com/altessa-s/go-optgen) at the version pinned in `devtools/go.mod`.
