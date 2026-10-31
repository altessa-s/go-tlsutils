// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlss3_test

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-tlsutils/internal/testhelpers"

	tlss3 "github.com/altessa-s/go-tlsutils/providers/s3"
)

// TestS3_GetClientCertificate pins that the provider serves its loaded
// certificate as the mTLS client certificate, follows reloads, and hands out
// copies.
func TestS3_GetClientCertificate(t *testing.T) {
	t.Parallel()
	client, certPEM, keyPEM := newMockClient(t)
	notifyCh := make(chan struct{}, 2)

	p, err := tlss3.New("my-bucket", "certs/server.crt", "certs/server.key", "",
		tlss3.WithS3Client(client),
		tlss3.WithPollInterval(20*time.Millisecond),
		tlss3.WithReloadNotifyChan(notifyCh),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close(t.Context()) })
	<-notifyCh // initial load

	want, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	got, err := p.GetClientCertificate(&tls.CertificateRequestInfo{})
	require.NoError(t, err)
	require.Equal(t, want.Certificate, got.Certificate)

	got.Certificate = nil
	again, err := p.GetClientCertificate(&tls.CertificateRequestInfo{})
	require.NoError(t, err)
	require.Equal(t, want.Certificate, again.Certificate, "callers get a copy")

	certPEM2, keyPEM2, _ := testhelpers.SelfSignedCert(t)
	client.SetObject("certs/server.crt", &mockObject{data: certPEM2, etag: `"etag-cert-2"`})
	client.SetObject("certs/server.key", &mockObject{data: keyPEM2, etag: `"etag-key-2"`})
	<-notifyCh // reload

	want2, err := tls.X509KeyPair(certPEM2, keyPEM2)
	require.NoError(t, err)
	reloaded, err := p.GetClientCertificate(&tls.CertificateRequestInfo{})
	require.NoError(t, err)
	require.Equal(t, want2.Certificate, reloaded.Certificate)
}
