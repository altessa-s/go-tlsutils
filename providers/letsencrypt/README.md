# letsencrypt

```go
import "github.com/altessa-s/go-tlsutils/providers/letsencrypt"
```

Package `tlsletsencrypt` provides a Let's Encrypt TLS certificate provider using HTTP-01 and TLS-ALPN-01 ACME challenges.
It manages certificate issuance, renewal, and caching.

`Close(ctx)` shuts down the provider's HTTP challenge server and waits for its goroutines until the context is done. If graceful shutdown fails, it force-closes active connections. The provider rejects new server starts and certificate requests after closing.

The upstream `autocert` API has no way to stop its internal renewal timer once started. The timer continues running until process exit.

## HTTP-01 challenge server

`StartHTTPServer(addr, fallback)` listens on the port in `addr` (`":8080"`, `"0.0.0.0:80"`); a host-only or empty `addr` listens on port 80.
ACME validation always connects to port 80, so a non-80 port needs a forward from public port 80.
