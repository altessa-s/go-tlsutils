# certconfig

```go
import "github.com/altessa-s/go-tlsutils/providers/internal/certconfig"
```

Internal reload steps shared by the [file](../../file) and [s3](../../s3) providers.

## Functions

| Function | Description                                                                                       |
|----------|---------------------------------------------------------------------------------------------------|
| `Build`  | Default server TLS config for a loaded certificate, with OCSP stapling installed before publication |
| `Notify` | Signal a reload channel without blocking; a nil or full channel is skipped                         |
