# letsencrypt

```go
import "github.com/altessa-s/go-tlsutils/providers/letsencrypt"
```

Package `tlsletsencrypt` provides a Let's Encrypt TLS certificate provider using HTTP-01 ACME challenges. Wraps `autocert` for automatic certificate
management with renewal and caching.

## HTTP-01 challenge server

`StartHTTPServer(addr, fallback)` listens on the port in `addr` (`":8080"`, `"0.0.0.0:80"`); a host-only or empty `addr` listens on port 80.
ACME validation always connects to port 80, so a non-80 port needs a forward from public port 80.
