# vault

```go
import "github.com/altessa-s/go-tlsutils/providers/vault"
```

Package `tlsvault` provides a HashiCorp Vault PKI engine certificate provider. Generates certificates dynamically and supports automatic renewal.

## Authentication

| Option                                                    | Use                                                                                        |
|-----------------------------------------------------------|--------------------------------------------------------------------------------------------|
| `WithStaticToken(token)`                                  | Fixed token, never renewed                                                                 |
| `WithRenewableToken(NewToken(initial, ttl, renewBefore))` | Renewable token, renewed in the background after the first issuance; `Close` stops renewal |
| `WithVc(client)`                                          | Pre-authenticated `*api.Client`; the provider does not manage its token                    |

`WithRenewableToken` returns `ErrInvalidToken` for a nil token or an empty initial token. `Close` is safe whether or not the token
ever authenticated. `GetCertificate` and `GetClientCertificate` return `ErrNilHandshakeInfo` for nil handshake info; info built outside
a live handshake (no context) is accepted and stapling runs under the default timeout.
