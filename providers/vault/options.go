// Copyright 2021-2026 ALTESSA SOLUTIONS INC. All rights reserved.
// Use of this source code is governed by license that can be found in
// the LICENSE file.

package tlsvault

//go:generate optgen generate --type=options --option-error  --all-fields

import (
	"errors"
	"log/slog"
	"net"
	"net/url"
	"time"

	coreerrs "github.com/altessa-s/go-atlas-core/errors"
	tlsutils "github.com/altessa-s/go-tlsutils"
	vaultApi "github.com/hashicorp/vault/api"
)

var (
	// ErrInvalidIP is returned when an invalid IP address is provided.
	ErrInvalidIP = errors.New("invalid IP")
	// ErrInvalidEndpoint is returned when an invalid Vault endpoint URL is provided.
	ErrInvalidEndpoint = errors.New("invalid endpoint")
	// ErrInvalidToken is returned by [WithRenewableToken] when the token is
	// nil or carries no initial token.
	ErrInvalidToken = errors.New("invalid renewable token")
	// ErrNilHandshakeInfo is returned by [Vault.GetCertificate] and
	// [Vault.GetClientCertificate] when called with nil handshake info.
	ErrNilHandshakeInfo = errors.New("nil handshake info")
)

// Token represents a renewable Vault authentication token.
// Create it with [NewToken] and pass it to [WithRenewableToken] for automatic
// token renewal.
type Token struct {
	initialToken string
	ttl          time.Duration
	renewBefore  time.Duration
}

// NewToken returns a renewable token. initial must be a renewable Vault token;
// ttl is the lifetime requested on each renewal and renewBefore how long
// before expiry a renewal is attempted. A non-positive ttl or renewBefore
// selects the issuer defaults (24h and 30m).
func NewToken(initial string, ttl, renewBefore time.Duration) *Token {
	return &Token{initialToken: initial, ttl: ttl, renewBefore: renewBefore}
}

type options struct {
	vc                        *vaultApi.Client
	endpoint                  *url.URL `opt:"-"`
	commonName                string
	cacheDir                  string
	role                      string
	subjectAlternativeNames   []string
	ipSubjectAlternativeNames []net.IP      `optgen:"parseip,err=ErrInvalidIP"`
	renewBefore               time.Duration `optgen:"default=time.Minute*10"`
	token                     any           `opt:"-"`
	logger                    *slog.Logger
	ocspStapler               tlsutils.OCSPStapler `optgen:"notnil"`
}

// WithEndpoint sets the Vault server endpoint URL.
// The URL must include the scheme (http or https).
func WithEndpoint(endpoint string) Option {
	return func(o *options) error {
		u, err := parseEndpoint(endpoint)
		if err != nil {
			return err
		}
		o.endpoint = u
		return nil
	}
}

// WithStaticToken sets a static authentication token for Vault.
// Use this for tokens that do not require renewal.
func WithStaticToken(st string) Option {
	return func(o *options) error {
		o.token = st
		return nil
	}
}

// WithRenewableToken sets a renewable authentication token for Vault.
// The token will be automatically renewed before expiration.
// It returns [ErrInvalidToken] when t is nil or has no initial token.
func WithRenewableToken(t *Token) Option {
	return func(o *options) error {
		if t == nil || t.initialToken == "" {
			return ErrInvalidToken
		}
		o.token = t
		return nil
	}
}

func parseEndpoint(endpoint string) (*url.URL, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, coreerrs.Wrapf(ErrInvalidEndpoint, "%v", err)
	}

	return &url.URL{
		Scheme: u.Scheme,
		Host:   u.Host,
	}, nil
}
