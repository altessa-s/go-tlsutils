// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlsletsencrypt_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"

	"golang.org/x/crypto/acme"

	"github.com/altessa-s/go-tlsutils/internal/testhelpers"

	tlsletsencrypt "github.com/altessa-s/go-tlsutils/providers/letsencrypt"
)

type acmeTransportFunc func(*http.Request) (*http.Response, error)

func (f acmeTransportFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestClose_StopsCertificateRenewal(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		validFor time.Duration
		renewing bool
	}{
		{name: "waiting on timer", validFor: 72 * time.Hour},
		{name: "in-flight renewal", validFor: 24 * time.Hour, renewing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				const domain = "example.com"

				dir := t.TempDir()
				ca := testhelpers.NewCA(t)
				cert := ca.SignLeaf(t, testhelpers.WithDNSNames(domain), func(leaf *x509.Certificate) {
					leaf.NotAfter = time.Now().Add(tc.validFor)
				})
				key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
				require.NoError(t, err)

				cache := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
				cache = append(cache, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})...)
				require.NoError(t, os.WriteFile(filepath.Join(dir, domain), cache, 0600))

				var started, finished int

				client := &acme.Client{
					DirectoryURL: "https://acme.example.com/directory",
					HTTPClient: &http.Client{Transport: acmeTransportFunc(func(req *http.Request) (*http.Response, error) {
						started++

						<-req.Context().Done()

						finished++

						return nil, req.Context().Err()
					})},
				}
				le := newProvider(t, tlsletsencrypt.WithCacheDir(dir), tlsletsencrypt.WithClient(client))
				cfg, err := le.TLSConfig()
				require.NoError(t, err)

				hello := &tls.ClientHelloInfo{ServerName: domain, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}}
				cached, err := cfg.GetCertificate(hello)
				require.NoError(t, err)
				require.Equal(t, cert.Certificate, cached.Certificate)
				synctest.Wait()

				wantRequests := 0
				if tc.renewing {
					wantRequests = 1
				}

				require.Equal(t, wantRequests, started)
				require.Zero(t, finished)

				require.NoError(t, le.Close(t.Context()))
				require.Equal(t, wantRequests, finished, "Close must wait for in-flight renewal to exit")
				time.Sleep(72 * time.Hour)
				synctest.Wait()
				require.Equal(t, wantRequests, started, "renewal must stay stopped after Close")

				_, err = cfg.GetCertificate(hello)
				require.ErrorIs(t, err, tlsletsencrypt.ErrClosed)
				require.ErrorIs(t, le.StartHTTPServer("127.0.0.1:0", nil), tlsletsencrypt.ErrClosed)
				require.NoError(t, le.Close(t.Context()))
			})
		})
	}
}
