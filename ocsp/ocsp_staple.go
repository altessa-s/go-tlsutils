// Copyright 2021-2026 ALTESSA SOLUTIONS INC. All rights reserved.
// Use of this source code is governed by license that can be found in
// the LICENSE file.

package ocsp

import (
	"context"
	"crypto/tls"
	"errors"
	"slices"
	"strings"

	coremaps "github.com/altessa-s/go-atlas-core/collections/maps"
	coreerrs "github.com/altessa-s/go-atlas-core/errors"
	tlsutils "github.com/altessa-s/go-tlsutils"
)

// FailureModeReporter is an optional interface for OCSP staplers that expose
// a [FailureMode]. [StapleOCSPToConfig] and [StapleCertificate] consult it to
// decide whether a failed staple-fetch aborts the handshake (Hard) or falls
// through with the unstapled certificate (Soft). It is implemented by
// [*Stapler]; an OCSPStapler without it is treated as Soft.
//
// A decorator around a stapler (metrics, tracing, caching) must implement
// FailureModeReporter by forwarding to the wrapped stapler, or a Hard-mode
// stapler silently degrades to Soft.
type FailureModeReporter interface {
	FailureMode() FailureMode
}

var _ FailureModeReporter = (*Stapler)(nil)

// resolveFailureMode reports the stapler's configured FailureMode,
// defaulting to Soft for staplers that don't expose one.
func resolveFailureMode(stapler tlsutils.OCSPStapler) FailureMode {
	if fma, ok := stapler.(FailureModeReporter); ok {
		return fma.FailureMode()
	}
	return FailureModeSoft
}

// stapleOrEnforce wraps the common "fetch + decide based on failure
// mode" flow used by both server and client certificate paths.
// Returns (certWithStaple, nil) on success, (cert, nil) in Soft mode
// when the staple is missing, or (nil, error) in Hard mode.
func stapleOrEnforce(ctx context.Context, stapler tlsutils.OCSPStapler, cert *tls.Certificate) (*tls.Certificate, error) {
	ocspResp, err := stapler.GetOCSPStaple(ctx, cert)
	if err == nil && len(ocspResp) > 0 {
		return tlsutils.CloneCertificateWithOCSPStaple(cert, ocspResp), nil
	}

	if resolveFailureMode(stapler) == FailureModeHard {
		if err != nil {
			return nil, coreerrs.WrapOperation(err, "ocsp staple required (hard-fail mode)")
		}
		return nil, errors.New("ocsp staple required (hard-fail mode): empty response")
	}

	// Soft mode: surrender the staple but still serve the certificate.
	return cert, nil
}

// StapleCertificate fetches an OCSP staple for cert and returns a stapled copy,
// honoring the stapler's [FailureMode]: a Hard-mode stapler returns an error
// when no valid staple can be produced, while Soft mode returns the unstapled
// certificate. Use this from per-certificate callbacks (GetCertificate /
// GetClientCertificate) where [StapleOCSPToConfig] cannot be applied.
//
// Returns cert unchanged when stapler or cert is nil.
func StapleCertificate(ctx context.Context, stapler tlsutils.OCSPStapler, cert *tls.Certificate) (*tls.Certificate, error) {
	if stapler == nil || cert == nil {
		return cert, nil
	}
	return stapleOrEnforce(ctx, stapler, cert)
}

// StapleOCSPToConfig adds OCSP stapling to a TLS config.
// It wraps the GetCertificate and GetClientCertificate functions to add OCSP staples.
// If the config already has these functions, they will be wrapped to preserve existing behavior.
// The TLS handshake context is used for OCSP requests.
//
// Failure mode (see [FailureMode]) is read from the stapler: a Hard-mode
// stapler aborts the handshake when no valid OCSP response can be
// produced; the default Soft-mode behavior serves the certificate
// without a staple.
//
// crypto/tls serves a static certificate from config.Certificates without
// calling GetCertificate when the client sends no SNI, which would bypass
// stapling and Hard-mode enforcement. StapleOCSPToConfig therefore moves
// config.Certificates (and NameToCertificate) into the wrapped GetCertificate,
// leaving those fields empty, and reproduces crypto/tls's selection there: the
// original GetCertificate when set and either SNI is present or no static
// certificate exists, then NameToCertificate, the first certificate the client
// supports, and finally the first one. When GetClientCertificate is unset, the
// static certificates stay available to the client side through an installed
// GetClientCertificate that selects like crypto/tls and, as before, does not
// staple. Call it after Certificates is populated and do not repopulate
// Certificates afterwards: a non-empty Certificates reopens the no-SNI path.
// Configs returned by GetConfigForClient are not wrapped; apply
// StapleOCSPToConfig to each of them. Enforcement applies to full handshakes —
// a resumed session does not select a certificate again.
//
// Example:
//
//	config := tlsutils.DefaultTLSConfig()
//	ocsp.StapleOCSPToConfig(config, stapler)
func StapleOCSPToConfig(config *tls.Config, stapler tlsutils.OCSPStapler) error {
	if config == nil || stapler == nil {
		return errors.New("invalid config or stapler")
	}

	// Take ownership of the static certificates so every full handshake —
	// with or without SNI — goes through the enforcing callback.
	statics := slices.Clone(config.Certificates)
	nameToCert := coremaps.NewImmutableMap(config.NameToCertificate) //nolint:staticcheck // reproduces crypto/tls selection
	config.Certificates = nil
	config.NameToCertificate = nil //nolint:staticcheck // moved into the callback with Certificates

	// Store original GetCertificate function
	originalGetCert := config.GetCertificate

	// Wrap GetCertificate to add OCSP stapling
	config.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := selectServerCertificate(hello, originalGetCert, statics, nameToCert)
		if err != nil {
			return nil, err
		}

		// Apply timeout to prevent slow OCSP responses from blocking TLS handshake
		ctx, cancel := context.WithTimeout(hello.Context(), handshakeOCSPTimeout)
		defer cancel()

		return stapleOrEnforce(ctx, stapler, cert)
	}

	// Also handle client certificates if needed
	originalGetClientCert := config.GetClientCertificate
	switch {
	case originalGetClientCert != nil:
		config.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, err := originalGetClientCert(info)
			if err != nil {
				return nil, err
			}

			// Apply timeout to prevent slow OCSP responses from blocking TLS handshake
			ctx, cancel := context.WithTimeout(info.Context(), handshakeOCSPTimeout)
			defer cancel()

			return stapleOrEnforce(ctx, stapler, cert)
		}
	case len(statics) > 0:
		// Keep the moved certificates usable by a client-side handshake exactly
		// as crypto/tls would pick them; static client certificates were never
		// stapled, so this path does not staple either.
		config.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			for i := range statics {
				if info.SupportsCertificate(&statics[i]) == nil {
					return &statics[i], nil
				}
			}
			return new(tls.Certificate), nil
		}
	}

	return nil
}

// selectServerCertificate mirrors crypto/tls (*Config).getCertificate over the
// certificates StapleOCSPToConfig moved out of the config.
func selectServerCertificate(
	hello *tls.ClientHelloInfo,
	getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error),
	statics []tls.Certificate,
	nameToCert *coremaps.ImmutableMap[string, *tls.Certificate],
) (*tls.Certificate, error) {
	if getCert != nil && (len(statics) == 0 || hello.ServerName != "") {
		cert, err := getCert(hello)
		if cert != nil || err != nil {
			return cert, err
		}
	}

	switch len(statics) {
	case 0:
		return nil, errors.New("no certificates available")
	case 1:
		return &statics[0], nil
	}

	if nameToCert != nil {
		name := strings.ToLower(hello.ServerName)
		if cert, ok := nameToCert.Get(name); ok {
			return cert, nil
		}
		if name != "" {
			labels := strings.Split(name, ".")
			labels[0] = "*"
			if cert, ok := nameToCert.Get(strings.Join(labels, ".")); ok {
				return cert, nil
			}
		}
	}

	for i := range statics {
		if hello.SupportsCertificate(&statics[i]) == nil {
			return &statics[i], nil
		}
	}
	return &statics[0], nil
}
