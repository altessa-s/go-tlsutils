// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package certconfig

import (
	"context"
	"crypto/tls"
	"log/slog"

	"github.com/altessa-s/go-tlsutils/ocsp"

	tlsutils "github.com/altessa-s/go-tlsutils"
)

// Build returns the default server TLS config serving cert, with OCSP
// stapling installed when stapler is non-nil. A stapling failure is logged
// and the config is returned without it. The config is complete when
// returned: once published it must not be mutated, or a concurrent Clone
// races with the write and may return a config without the stapling callback.
func Build(ctx context.Context, cert *tls.Certificate, stapler tlsutils.OCSPStapler, logger *slog.Logger) *tls.Config {
	cfg := tlsutils.DefaultTLSConfig()
	cfg.Certificates = []tls.Certificate{*cert}

	if stapler != nil {
		//nolint:contextcheck // closures obtain context from TLS handshake info, not from caller
		if err := ocsp.StapleOCSPToConfig(cfg, stapler); err != nil {
			logger.WarnContext(ctx, "failed to apply OCSP stapling to reloaded certificate", slog.Any("error", err))
		}
	}
	return cfg
}

// Notify signals ch without blocking; a nil or full channel is skipped.
func Notify(ch chan<- struct{}) {
	if ch == nil {
		return
	}
	select {
	case ch <- struct{}{}:
	default:
	}
}
