# docker

```go
import "github.com/altessa-s/go-tlsutils/integration/docker"
```

Docker-backed integration tests: each certificate provider runs against a real backend started with
[testcontainers-go](https://github.com/testcontainers/testcontainers-go) and must complete a TLS handshake verified against that backend's CA. The tests
live in a nested module, so testcontainers never enters the library's `go.mod`. They build only with the `integration_docker` tag.

## Prerequisites

| Requirement | Notes                                                                                                       |
|-------------|-------------------------------------------------------------------------------------------------------------|
| Docker      | Any provider testcontainers can reach (Docker Desktop, Colima, a Linux daemon, `DOCKER_HOST`)               |
| Network     | Images are pulled on first run: `hashicorp/vault`, `cgr.dev/chainguard/minio`, `ghcr.io/letsencrypt/pebble` |

Every test calls `testcontainers.SkipIfProviderIsNotHealthy` first, so the suite skips cleanly on a machine without Docker.

## Running

```sh
make test-integration-docker
# or, from the repository root:
go -C integration/docker test -tags integration_docker ./...
```

The module replaces `github.com/altessa-s/go-tlsutils` with `../..`, so the tests always exercise the working tree.

## Scenarios

| Test                | Backend                                     | What it proves                                                                                                                                                                               |
|---------------------|---------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `TestVaultPKI`      | Vault dev server (`modules/vault`)          | PKI mount, root CA and role created through the Vault API; `providers/vault` issues a certificate; the handshake verifies against the Vault root and the served chain carries the issuing CA |
| `TestMinIOProvider` | MinIO (`modules/minio`)                     | Leaf, intermediate and key uploaded with aws-sdk-go-v2; `providers/s3` (path-style endpoint, static credentials) serves the chain; after an overwrite the ETag poll serves the new leaf      |
| `TestPebbleACME`    | Pebble ACME test server (generic container) | `providers/letsencrypt` pointed at Pebble's directory through `WithClient`; the first handshake drives the ACME order and verifies against Pebble's root                                     |

## Notes

- **MinIO image.** The upstream `minio/minio` and `quay.io/minio/minio` images are no longer publicly pullable, so the test uses Chainguard's build,
  which the free tier publishes only as `latest`. It runs as a non-root user, so the server stores data under `/tmp`.
- **Pebble challenges.** Pebble runs with `PEBBLE_VA_ALWAYS_VALID=1` and `PEBBLE_WFE_NONCEREJECT=0`: no challenge has to reach the test process from
  inside the container, and nonce rejection does not add retries. The ACME HTTP client trusts the minica shipped in the image and verifies the `pebble`
  SAN; the issuing root is fetched from the management interface at `/roots/0`.
- **SPIRE is out of scope.** The SPIFFE Workload API is served on a unix socket, and unix sockets do not cross Docker Desktop bind mounts, so `spiffe`
  cannot be exercised from the host against a containerized SPIRE agent.
