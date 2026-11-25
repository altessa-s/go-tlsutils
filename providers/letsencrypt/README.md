# letsencrypt

```go
import "github.com/altessa-s/go-tlsutils/providers/letsencrypt"
```

Package `tlsletsencrypt` provides a Let's Encrypt TLS certificate provider using HTTP-01 and TLS-ALPN-01 ACME challenges.
It manages certificate issuance, renewal, and caching.

`Close(ctx)` cancels certificate issuance and renewal, shuts down the HTTP challenge server, and waits for manager work to exit within the context deadline.
After closing, create a new provider to resume certificate management.

## HTTP-01 challenge server

`StartHTTPServer(addr, fallback)` listens on the port in `addr` (`":8080"`, `"0.0.0.0:80"`); a host-only or empty `addr` listens on port 80.
ACME validation always connects to port 80, so a non-80 port needs a forward from public port 80.
