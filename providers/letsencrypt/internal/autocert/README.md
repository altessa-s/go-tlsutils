# Autocert adapter

`autocert.go` and `renewal.go` are adapted from the BSD-licensed
`golang.org/x/crypto/acme/autocert` v0.58.0. The upstream manager has no
public shutdown method. This copy preserves the ACME flow, challenge handling,
cache format, and renewal schedule. It ties renewal timers, issuance, and
background cleanup to the manager's lifetime so the provider can cancel and
wait for them.

When updating `golang.org/x/crypto`, review its autocert changes and keep the
shutdown behavior covered by the provider's renewal tests. The cache and ACME
client still come from the upstream module.
