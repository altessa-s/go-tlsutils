module github.com/altessa-s/go-tlsutils/spiffe

go 1.27.0

toolchain go1.27.3

// Development: build against the root module in this checkout. Consumers
// ignore this directive; releases require a tagged root version above.
replace github.com/altessa-s/go-tlsutils => ../

require (
	github.com/altessa-s/go-atlas-core v0.2.0
	github.com/altessa-s/go-tlsutils v0.1.0
	github.com/spiffe/go-spiffe/v2 v2.9.0
	github.com/stretchr/testify v1.12.1
	google.golang.org/grpc v1.85.0
)

require (
	github.com/Microsoft/go-winio v0.6.4 // indirect
	github.com/go-jose/go-jose/v4 v4.1.7 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261026165753-2ffab32bce7e // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
