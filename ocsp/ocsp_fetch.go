// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package ocsp

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"

	coreerrs "github.com/altessa-s/go-atlas-core/errors"
)

// fetchOCSPResponse fetches a fresh OCSP response for the certificate.
// It tries each OCSP server URL in the certificate with retry policy if configured.
// Returns the OCSP response bytes and the next update time.
func (s *Stapler) fetchOCSPResponse(ctx context.Context, cert *tls.Certificate, leafCert *x509.Certificate) ([]byte, time.Time, error) {
	if len(leafCert.OCSPServer) == 0 {
		return nil, time.Time{}, errors.New("no OCSP server specified in certificate")
	}

	// Find issuer certificate
	var issuerCert *x509.Certificate
	if len(cert.Certificate) > 1 {
		var err error
		issuerCert, err = x509.ParseCertificate(cert.Certificate[1])
		if err != nil {
			return nil, time.Time{}, coreerrs.WrapOperation(err, "parse issuer certificate")
		}
	} else {
		return nil, time.Time{}, errors.New("issuer certificate not found in chain")
	}

	// Create OCSP request
	ocspReq, err := ocsp.CreateRequest(leafCert, issuerCert, nil)
	if err != nil {
		return nil, time.Time{}, coreerrs.WrapOperation(err, "create OCSP request")
	}

	var ocspResp []byte
	var parsedResp *ocsp.Response

	// Try each OCSP server with retry policy
	for i, ocspURL := range leafCert.OCSPServer {
		// Check context before trying next server
		select {
		case <-ctx.Done():
			return nil, time.Time{}, ctx.Err()
		default:
		}

		s.logger.DebugContext(ctx, "trying OCSP server",
			slog.Int("index", i+1),
			slog.Int("total", len(leafCert.OCSPServer)),
			slog.String("url", ocspURL))

		var retryErr error

		requestFunc := func() error {
			var err error
			ocspResp, parsedResp, err = s.requestOCSP(ctx, ocspURL, ocspReq, leafCert, issuerCert)
			return err
		}

		if s.retryPolicy != nil {
			// Use retry policy if available
			retryErr = ExecuteWithRetry(ctx, s.retryPolicy, requestFunc,
				WithOnRetry(func(attempt int, err error, nextDelay time.Duration) {
					s.logger.ErrorContext(ctx, "ocsp request failed, retrying",
						slog.Int("attempt", attempt+1),
						slog.Duration("next_delay", nextDelay),
						slog.Any("error", err))
				}))
		} else {
			// Single attempt without retry
			retryErr = requestFunc()
		}

		if retryErr == nil {
			// Success with this OCSP server
			break
		}

		// Log failure and try next server
		s.logger.ErrorContext(ctx, "failed to get OCSP response",
			slog.String("url", ocspURL),
			slog.Any("error", retryErr))
		if i == len(leafCert.OCSPServer)-1 {
			// Last server failed
			return nil, time.Time{}, coreerrs.WrapOperation(retryErr, "fetch from all OCSP servers")
		}
	}

	// Check certificate status
	if parsedResp.Status != ocsp.Good {
		return nil, time.Time{}, fmt.Errorf("certificate status is not good: %v", parsedResp.Status)
	}

	// The parser verifies the signature but not freshness: a replayed or
	// not-yet-valid "good" response must not be stapled (clients reject it, and
	// in Hard mode it would mask a revocation that happened after NextUpdate).
	now := time.Now()
	if err := checkFreshness(parsedResp, now, s.maxResponseAge); err != nil {
		return nil, time.Time{}, err
	}

	// Calculate next update time
	nextUpdate := parsedResp.NextUpdate
	if nextUpdate.IsZero() || nextUpdate.After(now.Add(7*24*time.Hour)) {
		// If no next update or too far in the future, refresh in 24 hours
		nextUpdate = now.Add(DefaultOCSPExpiry)
	}
	if parsedResp.NextUpdate.IsZero() {
		// A response without a nextUpdate is only trusted until thisUpdate plus
		// the maximum response age; never serve it from cache past that.
		if deadline := parsedResp.ThisUpdate.Add(s.maxResponseAge); deadline.Before(nextUpdate) {
			nextUpdate = deadline
		}
	}

	return ocspResp, nextUpdate, nil
}

// requestOCSP posts ocspReq to one OCSP server and returns the raw response
// and its parse, bound to leafCert's serial and signed by issuerCert. The raw
// bytes are returned whenever they were read, even when parsing fails.
func (s *Stapler) requestOCSP(
	ctx context.Context, ocspURL string, ocspReq []byte, leafCert, issuerCert *x509.Certificate,
) ([]byte, *ocsp.Response, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "POST", ocspURL, bytes.NewReader(ocspReq))
	if err != nil {
		return nil, nil, coreerrs.WrapOperation(err, "create HTTP request")
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")

	// Request gzip compression if enabled
	if s.enableCompression {
		httpReq.Header.Set("Accept-Encoding", "gzip")
	}

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, nil, coreerrs.WrapOperation(err, "execute OCSP request")
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("OCSP server returned status %d", resp.StatusCode)
	}

	var responseBody io.Reader = resp.Body

	// Handle compressed response
	if s.enableCompression {
		contentEncoding := resp.Header.Get("Content-Encoding")
		if strings.Contains(contentEncoding, "gzip") {
			gzipReader, gzipErr := gzip.NewReader(resp.Body)
			if gzipErr != nil {
				return nil, nil, coreerrs.WrapOperation(gzipErr, "create gzip reader for OCSP response")
			}
			defer gzipReader.Close() //nolint:errcheck
			responseBody = gzipReader

			s.logger.DebugContext(ctx, "received gzip-compressed OCSP response")
		}
	}

	ocspResp, err := io.ReadAll(io.LimitReader(responseBody, maxOCSPResponseSize+1))
	if err != nil {
		return ocspResp, nil, coreerrs.WrapOperation(err, "read OCSP response")
	}
	if len(ocspResp) > maxOCSPResponseSize {
		return ocspResp, nil, fmt.Errorf("OCSP response exceeds %d bytes", maxOCSPResponseSize)
	}

	// ParseResponseForCert also binds the response to the leaf's serial:
	// a CA-signed response for a sibling certificate must not be stapled.
	parsedResp, err := ocsp.ParseResponseForCert(ocspResp, leafCert, issuerCert)
	if err != nil {
		return ocspResp, parsedResp, coreerrs.WrapOperation(err, "parse OCSP response")
	}

	return ocspResp, parsedResp, nil
}

// checkFreshness rejects a response whose validity window does not contain
// now, tolerating ocspClockSkew on both ends. A response without a nextUpdate
// is valid until its thisUpdate plus maxAge.
func checkFreshness(resp *ocsp.Response, now time.Time, maxAge time.Duration) error {
	if resp.ThisUpdate.After(now.Add(ocspClockSkew)) {
		return fmt.Errorf("%w: thisUpdate %s is in the future", ErrStaleResponse, resp.ThisUpdate.Format(time.RFC3339))
	}
	if !resp.NextUpdate.IsZero() && now.After(resp.NextUpdate.Add(ocspClockSkew)) {
		return fmt.Errorf("%w: nextUpdate %s has passed", ErrStaleResponse, resp.NextUpdate.Format(time.RFC3339))
	}
	if resp.NextUpdate.IsZero() && now.After(resp.ThisUpdate.Add(maxAge+ocspClockSkew)) {
		return fmt.Errorf("%w: thisUpdate %s is older than the maximum response age %s without a nextUpdate",
			ErrStaleResponse, resp.ThisUpdate.Format(time.RFC3339), maxAge)
	}
	return nil
}
