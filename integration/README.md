# integration

```go
import _ "github.com/altessa-s/go-tlsutils/integration" // test-only package
```

In-process, end-to-end tests that wire real go-tlsutils components together and drive real TLS handshakes over `net.Pipe` or loopback
listeners. OCSP staples come from a real responder built on `golang.org/x/crypto/ocsp` and served by `httptest`, signed by a CA from
[`internal/testhelpers`](../internal/testhelpers). The tests need no Docker, no network beyond loopback and no extra dependencies; the Docker-based
suite lives in [`docker`](docker).

## Scenarios

| Test                                           | Components                                    | What it proves                                                                                          |
|------------------------------------------------|-----------------------------------------------|---------------------------------------------------------------------------------------------------------|
| `TestFileProvider_StapledHandshake`            | `providers/file`, `ocsp` (Soft)               | A leaf+intermediate chain verifies against the root pool and carries a Good staple for the served leaf. |
| `TestFileProvider_RotationUnderLoad`           | `providers/file` watcher, reload notify, `ocsp` | Rewriting key and certificate under concurrent handshakes fails none; after the notify new handshakes see the new leaf. |
| `TestFailureModes`                             | `providers/file`, `ocsp` (Hard / Soft)        | Hard rejects the handshake on a 500 or revoked answer; Soft with the responder down serves without a staple. |
| `TestOCSP_SingleflightAcrossHandshakes`        | `providers/file`, `ocsp`                      | Concurrent handshakes on a cold cache hit the responder exactly once.                                   |
| `TestS3Provider_StapledHandshakeAndReload`     | `providers/s3` with an in-memory `S3API`, `ocsp` | The S3 chain is stapled and verified; an ETag change picked up by polling swaps in the new leaf.      |
| `TestVaultProvider_IssuedCertificateHandshake` | `providers/vault` against a fake PKI sign endpoint, `ocsp` | The issued certificate is served with the issuing CA in the chain, verified, stapled and cached. |
| `TestMutualTLS_FileProviderClientCertificate`  | `tlsutils.ClientTLSConfig`, `providers/file`  | A file-provider client certificate passes a server that requires and verifies it; an untrusted one is rejected. |

## Running

The test files carry the `integration` build tag, so `go test ./...` compiles the package and reports no test files.

```sh
make test-integration
go test -tags integration ./integration/...
go test -tags integration -race -count=2 ./integration/...
```
