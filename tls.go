// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlsutils

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/youmark/pkcs8"

	"github.com/altessa-s/go-atlas-core/io/files"

	coreerrs "github.com/altessa-s/go-atlas-core/errors"
)

const (
	pemTypeCertificate         = "CERTIFICATE"
	pemTypePrivateKey          = "PRIVATE KEY"
	pemTypeEncryptedPrivateKey = "ENCRYPTED PRIVATE KEY"

	// maxKeyFilePermissions is the maximum allowed file mode for private key files.
	// Key files must not be readable by group or others (i.e., at most 0600).
	maxKeyFilePermissions os.FileMode = 0o600
)

// OCSPStapler defines the interface for OCSP stapling functionality.
// OCSP stapling improves TLS handshake performance by including certificate
// revocation status in the TLS handshake, reducing client-side OCSP requests.
type OCSPStapler interface {
	// GetOCSPStaple returns the OCSP staple for the given certificate.
	// The context controls the HTTP request timeout and cancellation.
	GetOCSPStaple(ctx context.Context, cert *tls.Certificate) ([]byte, error)
	// RunRefreshAll refreshes all OCSP responses in the cache that need it.
	// This method is designed to be called periodically via an external scheduler.
	RunRefreshAll(ctx context.Context) error
}

// CloneCertificateWithOCSPStaple creates a shallow copy of the certificate with the provided OCSP staple.
// This is useful when updating OCSP responses without modifying the original certificate.
func CloneCertificateWithOCSPStaple(cert *tls.Certificate, ocspStaple []byte) *tls.Certificate {
	clone := *cert
	clone.OCSPStaple = ocspStaple
	return &clone
}

var cipherSuits = []uint16{
	// 1.3
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
	// 1.2 (ECDSA certificates)
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	// 1.2 (RSA certificates) — without these an RSA cert cannot complete a
	// TLS 1.2 handshake against this pinned list. All remain AEAD/forward-secret.
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
}

// readKeyFile reads a private key file that must be a regular file not
// accessible by group or others (at most 0600). The permissions are checked
// on the descriptor that is then read, so the file cannot be swapped between
// the check and the read.
func readKeyFile(path string) ([]byte, error) {
	f, err := files.OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if mode := info.Mode().Perm(); mode&^maxKeyFilePermissions != 0 {
		return nil, fmt.Errorf("private key file %q has insecure permissions %04o, maximum allowed is %04o",
			path, mode, maxKeyFilePermissions)
	}
	return io.ReadAll(f)
}

// loadPEM builds a certificate from the chain in certData (leaf first) and
// the first private key in keyData, like tls.X509KeyPair: certificates are
// taken only from certData and the key only from keyData, so a key bundled
// into a certificate file never stands in for the key input. Every
// CERTIFICATE block is kept so the chain reaches the issuer; the key is
// decrypted with keyPassword when encrypted. tls.X509KeyPair then rejects a
// key that does not match the leaf.
func loadPEM(certData, keyData []byte, keyPassword string) (*tls.Certificate, error) {
	var chain []byte
	for rest := certData; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == pemTypeCertificate {
			chain = append(chain, pem.EncodeToMemory(block)...)
		}
	}

	signer, err := ParsePrivateKeyPEM(keyData, keyPassword)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, coreerrs.WrapOperation(err, "encode private key")
	}
	key := pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: der})

	cert, err := tls.X509KeyPair(chain, key)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// ErrInvalidPrivateKey indicates missing, malformed, unsupported, or excessively
// costly private key data. For encrypted keys, a decrypted payload that cannot be
// parsed instead returns ErrIncorrectPassword: unauthenticated encryption cannot
// always distinguish a wrong password from a corrupt key.
var ErrInvalidPrivateKey = errors.New("invalid private key")

// ErrIncorrectPassword indicates a decryption failure identified as an incorrect
// password. Unauthenticated encryption cannot distinguish all corrupt keys from
// incorrect passwords. It also indicates an encrypted payload that decrypts but
// cannot be parsed as a private key.
var ErrIncorrectPassword = errors.New("incorrect private key password")

// ErrPasswordRequired indicates an encrypted key was supplied without a password.
var ErrPasswordRequired = errors.New("private key password required")

// PrivateKeyError describes a private key parsing failure. Unwrap exposes its
// sentinel cause for errors.Is: ErrInvalidPrivateKey, ErrIncorrectPassword, or
// ErrPasswordRequired. Messages never include key data or passwords.
type PrivateKeyError struct {
	Err error
}

func (e *PrivateKeyError) Error() string {
	if e.Err == nil {
		return "parse private key"
	}
	return "parse private key: " + e.Err.Error()
}

// Unwrap returns the parsing failure's cause.
func (e *PrivateKeyError) Unwrap() error { return e.Err }

// ParsePrivateKeyPEM parses the first private key PEM block as a crypto.Signer.
// Certificates and other non-key blocks are skipped; missing or invalid keys
// return a *PrivateKeyError. Supported keys are Ed25519, ECDSA, and RSA in PKCS#8,
// PKCS#1, or SEC1 format, matching the TLS loading path.
// Password decrypts encrypted PKCS#8 and legacy encrypted PEM; it is ignored for
// unencrypted keys. An empty password is for unencrypted keys.
//
// Encrypted PKCS#8 keys allow only PBKDF2 (1 to 10,000,000 iterations) and
// scrypt (128*N*r <= 1 GiB). Scrypt requires power-of-two N from 2 to 1,048,576,
// r from 1 to 32, p from 1 to 16, and N*r*p <= 8,388,608. Unsupported KDFs or
// excessive costs return ErrInvalidPrivateKey before decryption. These limits
// also apply to TLS loading and reject keys previously accepted without bounds.
func ParsePrivateKeyPEM(pemData []byte, password string) (crypto.Signer, error) {
	for rest := pemData; ; {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return nil, &PrivateKeyError{Err: ErrInvalidPrivateKey}
		}
		rest = remaining
		if !strings.HasSuffix(block.Type, pemTypePrivateKey) {
			continue
		}
		plaintext, err := decodeKeyPEM(block, password)
		if err != nil {
			return nil, &PrivateKeyError{Err: err}
		}
		decoded, _ := pem.Decode(plaintext)
		if decoded == nil {
			return nil, &PrivateKeyError{Err: ErrInvalidPrivateKey}
		}
		// Match crypto/tls's DER format detection, independent of the PEM label.
		if key, err := x509.ParsePKCS1PrivateKey(decoded.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKCS8PrivateKey(decoded.Bytes); err == nil {
			switch key := key.(type) {
			case *rsa.PrivateKey:
				return key, nil
			case *ecdsa.PrivateKey:
				return key, nil
			case ed25519.PrivateKey:
				return key, nil
			default:
				return nil, &PrivateKeyError{Err: ErrInvalidPrivateKey}
			}
		}
		if key, err := x509.ParseECPrivateKey(decoded.Bytes); err == nil {
			return key, nil
		}
		// Legacy encryption can produce valid padding with the wrong password.
		// Treat unparseable plaintext consistently with the PKCS#8 decoder.
		if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck // SA1019: required for legacy PEM support
			return nil, &PrivateKeyError{Err: ErrIncorrectPassword}
		}
		return nil, &PrivateKeyError{Err: ErrInvalidPrivateKey}
	}
}

// decodeKeyPEM returns block as plaintext PEM, decrypting encrypted PKCS#8
// and legacy-encrypted (RFC 1423) keys with keyPassword.
func decodeKeyPEM(block *pem.Block, keyPassword string) (plaintext []byte, err error) {
	// Cipher parameters and KDF costs are validated before decryption. Keep
	// recovery as a last resort for unexpected dependency panics, without
	// exposing their payloads.
	defer func() {
		if recover() != nil {
			plaintext, err = nil, ErrInvalidPrivateKey
		}
	}()
	if block.Type == pemTypeEncryptedPrivateKey {
		if keyPassword == "" {
			return nil, ErrPasswordRequired
		}
		if err = validatePrivateKeyKDF(block.Bytes); err != nil {
			return nil, err
		}
		key, parseErr := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(keyPassword))
		if parseErr != nil {
			// The pinned dependency exposes this condition only as a string.
			if parseErr.Error() == "pkcs8: incorrect password" {
				return nil, ErrIncorrectPassword
			}
			return nil, ErrInvalidPrivateKey
		}
		der, marshalErr := x509.MarshalPKCS8PrivateKey(key)
		if marshalErr != nil {
			return nil, ErrInvalidPrivateKey
		}
		return pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: der}), nil
	}

	decrypted, encrypted, err := decryptLegacyPEMKey(block, keyPassword)
	if err != nil {
		return nil, err
	}
	if encrypted {
		return decrypted, nil
	}
	return pem.EncodeToMemory(block), nil
}

// LoadFromBytes loads a certificate and private key from raw PEM bytes.
// certPem may hold the full chain, leaf first; every certificate is kept.
// Certificates are read only from certPem and the private key only from
// keyPem.
// Supports multiple private key formats including PKCS#8, PKCS#1 (RSA), SEC1 (EC),
// and legacy-encrypted PEM formats. The keyPassword parameter is required for
// encrypted private keys and ignored for unencrypted keys.
//
// Encrypted PKCS#8 keys follow the KDF allowlist and cost limits documented in [ParsePrivateKeyPEM].
//
// Example:
//
//	cert, err := tlsutils.LoadFromBytes(certPem, keyPem, "password")
//	if err != nil {
//		log.Fatal(err)
//	}
func LoadFromBytes(certPem, keyPem []byte, keyPassword string) (*tls.Certificate, error) {
	return loadPEM(certPem, keyPem, keyPassword)
}

// LoadFromFile loads a certificate and private key from separate files.
// Supports multiple private key formats including PKCS#8, PKCS#1 (RSA), SEC1 (EC),
// and legacy-encrypted PEM formats. The keyPassword parameter is required for
// encrypted private keys and ignored for unencrypted keys.
//
// Encrypted PKCS#8 keys follow the KDF allowlist and cost limits documented in [ParsePrivateKeyPEM].
//
// Example:
//
//	cert, err := tlsutils.LoadFromFile("server.key", "server.crt", "password")
//	if err != nil {
//		log.Fatal(err)
//	}
func LoadFromFile(keyPath, certPath, keyPassword string) (*tls.Certificate, error) {
	certPem, err := files.ReadRegular(certPath)
	if err != nil {
		return nil, err
	}

	keyPem, err := readKeyFile(keyPath)
	if err != nil {
		return nil, err
	}

	return LoadFromBytes(certPem, keyPem, keyPassword)
}

// LoadFromConcatenatedFile loads a certificate and private key from a single file.
// The file should contain both the certificate and private key in PEM format;
// certificates after the leaf are kept as the chain.
// The keyPassword parameter is required for encrypted private keys.
//
// Encrypted PKCS#8 keys follow the KDF allowlist and cost limits documented in [ParsePrivateKeyPEM].
//
// Example:
//
//	cert, err := tlsutils.LoadFromConcatenatedFile("server.pem", "password")
//	if err != nil {
//		log.Fatal(err)
//	}
func LoadFromConcatenatedFile(certKeyFilePath, keyPassword string) (*tls.Certificate, error) {
	data, err := readKeyFile(certKeyFilePath)
	if err != nil {
		return nil, err
	}

	return loadPEM(data, data, keyPassword)
}

// DefaultTLSConfig returns a secure default TLS configuration.
// The configuration enforces TLS 1.2+ and uses modern cipher suites.
// Suitable for most server applications requiring secure connections.
//
// Example:
//
//	config := tlsutils.DefaultTLSConfig()
//	config.Certificates = []tls.Certificate{cert}
//	server := &http.Server{TLSConfig: config}
func DefaultTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: slices.Clone(cipherSuits),
	}
}

// DefaultTLSConfigStrict returns a server TLS configuration that
// requires TLS 1.3. Modern clients all support TLS 1.3; locking it as
// the minimum drops the long tail of weak suites the TLS 1.2 path
// allows and removes downgrade attack surface entirely. The
// CipherSuites field is intentionally left empty — for TLS 1.3 the
// stdlib enforces its own modern AEAD-only list and the TLS 1.2
// pinned suites are ignored.
//
// Example:
//
//	config := tlsutils.DefaultTLSConfigStrict()
//	config.Certificates = []tls.Certificate{cert}
//	server := &http.Server{TLSConfig: config}
func DefaultTLSConfigStrict() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
}

// DefaultClientTLSConfig returns a secure default TLS configuration for client connections.
// The configuration enforces TLS 1.2+ and sets the server name for certificate validation.
// The serverName parameter is used for SNI and certificate verification.
//
// Example:
//
//	config := tlsutils.DefaultClientTLSConfig("example.com")
//	conn, err := tls.Dial("tcp", "example.com:443", config)
func DefaultClientTLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: slices.Clone(cipherSuits),
		ServerName:   serverName,
	}
}

// DefaultClientTLSConfigStrict is the client-side counterpart of
// [DefaultTLSConfigStrict]. Use when you control both endpoints and
// want to force TLS 1.3 across the wire.
func DefaultClientTLSConfigStrict(serverName string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
	}
}

// clientCertificateSource supplies the client certificate presented during
// a TLS handshake. It is the consumer-side view of
// tlsproviders.ClientCertificate, declared here so this package does not
// import its own providers subpackage. The stdlib calls the method whenever
// the server requests a client certificate (mutual TLS).
type clientCertificateSource interface {
	GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error)
}

// ClientTLSConfig builds a TLS 1.3 client configuration that presents a
// client certificate supplied by src on every handshake, for mutual TLS on
// outgoing connections. The certificate is pulled per handshake, so a
// rotating source (file watcher, Vault lease) is reflected without rebuilding
// the config. serverName is used for SNI and server-certificate verification
// against the system roots; set RootCAs on the returned config to pin a
// private CA.
//
// Example:
//
//	cfg := tlsutils.ClientTLSConfig(provider, "peer.internal")
//	conn, err := tls.Dial("tcp", "peer.internal:8443", cfg)
func ClientTLSConfig(src clientCertificateSource, serverName string) *tls.Config {
	cfg := DefaultClientTLSConfigStrict(serverName)
	cfg.GetClientCertificate = src.GetClientCertificate
	return cfg
}

// DialContext opens a mutual-TLS connection to addr, presenting the client
// certificate from src. It is a thin convenience over [ClientTLSConfig] and
// [tls.Dialer]. An empty serverName lets the dialer derive it from addr.
//
// Example:
//
//	conn, err := tlsutils.DialContext(ctx, "tcp", "peer.internal:8443", provider, "")
func DialContext(ctx context.Context, network, addr string, src clientCertificateSource, serverName string) (net.Conn, error) {
	d := tls.Dialer{Config: ClientTLSConfig(src, serverName)}
	return d.DialContext(ctx, network, addr)
}

// ResolveMinTLSVersion translates a human-readable version string
// ("1.2" / "1.3") into the corresponding [tls.VersionTLSxx] constant.
// Empty or unrecognized inputs return the safe default ([tls.VersionTLS12])
// and report ok=false so callers can reject the config rather than
// silently accept a typo that would otherwise be ignored. Mirrors the
// project's safety-mode pattern of fail-safe-on-unknown.
//
// Recognized values (case-insensitive, leading/trailing space trimmed):
//   - "1.2", "tls1.2", "tlsv1.2" → [tls.VersionTLS12]
//   - "1.3", "tls1.3", "tlsv1.3" → [tls.VersionTLS13]
func ResolveMinTLSVersion(s string) (uint16, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1.2", "tls1.2", "tlsv1.2":
		return tls.VersionTLS12, true
	case "1.3", "tls1.3", "tlsv1.3":
		return tls.VersionTLS13, true
	default:
		return tls.VersionTLS12, false
	}
}

// decryptLegacyPEMKey decrypts a private key block encrypted with legacy PEM
// encryption (RFC 1423, marked by a DEK-Info header) when a password is set.
// It returns the re-encoded plaintext PEM and encrypted=true for such a
// block, and encrypted=false for any other block.
func decryptLegacyPEMKey(block *pem.Block, keyPassword string) (pemKey []byte, encrypted bool, err error) {
	if block.Headers == nil {
		return nil, false, nil
	}
	// Check if the PEM block is encrypted by looking for the DEK-Info header
	if _, ok := block.Headers["DEK-Info"]; !ok {
		return nil, false, nil
	}
	// Deprecated but required for legacy PEM encryption (RFC 1423).
	// Modern PKCS#8 encryption is handled by decodeKeyPEM.
	if !x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck // SA1019: required for legacy PEM support
		return nil, false, nil
	}
	if keyPassword == "" {
		return nil, false, ErrPasswordRequired
	}
	buf, err := x509.DecryptPEMBlock(block, []byte(keyPassword)) //nolint:staticcheck // SA1019: required for legacy PEM support
	if err != nil {
		if errors.Is(err, x509.IncorrectPasswordError) { //nolint:staticcheck // SA1019: required for legacy PEM support
			return nil, false, ErrIncorrectPassword
		}
		return nil, false, ErrInvalidPrivateKey
	}

	var encoded bytes.Buffer
	if err := pem.Encode(&encoded, &pem.Block{Type: block.Type, Bytes: buf}); err != nil {
		return nil, false, ErrInvalidPrivateKey
	}
	return encoded.Bytes(), true, nil
}

// BuildCAPool builds a certificate pool from CA certificate files.
// If a system is true, starts with the system's certificate pool.
// Additional CA certificates from caPath files are appended to the pool.
// Returns nil if no valid certificates are found.
//
// Example:
//
//	pool, err := tlsutils.BuildCAPool(true, "ca1.crt", "ca2.crt")
//	if err != nil {
//		log.Fatal(err)
//	}
//	config.RootCAs = pool
func BuildCAPool(system bool, caPath ...string) (*x509.CertPool, error) {
	var (
		pool *x509.CertPool
		err  error
	)

	if system {
		pool, err = x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
	}

	if pool == nil {
		pool = x509.NewCertPool()
	}

	for _, path := range caPath {
		caPem, err := files.ReadRegular(path)
		if err != nil {
			return nil, err
		}

		if !pool.AppendCertsFromPEM(caPem) {
			return nil, fmt.Errorf("failed to parse any certificates from CA file %s", path)
		}
	}

	return pool, nil
}

// ApplyMinTLSVersion resolves the YAML-supplied minVersion string into a
// tls.VersionTLSxx constant via [ResolveMinTLSVersion] and applies
// it to the provider-supplied tls.Config. When the operator pins TLS 1.3
// the legacy 1.2 cipher list seeded by the provider is cleared so the
// resulting config matches [DefaultTLSConfigStrict] semantics —
// otherwise CipherSuites stays populated with 1.2-only entries that the
// stdlib silently ignores under TLS 1.3 and operators reading the config
// would assume those suites are still meaningful.
//
// An empty minVersion (legacy callers, or YAML that omitted the field) is
// accepted as "leave the provider default in place"; any other unknown
// value is rejected so a typo (e.g. "v1.3") cannot silently fall back to
// the stdlib default.
func ApplyMinTLSVersion(tlsConfig *tls.Config, raw string) error {
	if raw == "" {
		return nil
	}
	v, ok := ResolveMinTLSVersion(raw)
	if !ok {
		return fmt.Errorf("unknown TLS version %q: supported values are 1.2, 1.3", raw)
	}
	tlsConfig.MinVersion = v
	if v == tls.VersionTLS13 {
		tlsConfig.CipherSuites = nil
	}
	return nil
}
