// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlsfile_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-tlsutils/internal/testhelpers"

	tlsutils "github.com/altessa-s/go-tlsutils"
	tlsfile "github.com/altessa-s/go-tlsutils/providers/file"
)

// TestFile_GetClientCertificate_MutualTLS pins that the provider can be passed straight
// to tlsutils.ClientTLSConfig and presents its loaded certificate to a server
// that requires one.
func TestFile_GetClientCertificate_MutualTLS(t *testing.T) {
	t.Parallel()
	ca := testhelpers.NewCA(t)
	serverCert := ca.SignLeaf(t, testhelpers.WithDNSNames("peer.internal"))
	clientLeaf := ca.SignLeaf(t, testhelpers.WithCommonName("client"),
		testhelpers.WithExtKeyUsage(x509.ExtKeyUsageClientAuth))

	certPath, keyPath := testhelpers.WriteTempCertFiles(t, pemCert(clientLeaf), pemKey(t, clientLeaf))
	provider, err := tlsfile.NewWithCertAndKey(certPath, keyPath, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = provider.Close(t.Context()) })

	got, err := provider.GetClientCertificate(&tls.CertificateRequestInfo{})
	require.NoError(t, err)
	require.Equal(t, clientLeaf.Certificate, got.Certificate)

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.Pool,
		MinVersion:   tls.VersionTLS13,
	}
	clientCfg := tlsutils.ClientTLSConfig(provider, "peer.internal")
	clientCfg.RootCAs = ca.Pool

	cConn, sConn := net.Pipe()
	t.Cleanup(func() { _ = cConn.Close(); _ = sConn.Close() })
	srv := tls.Server(sConn, serverCfg)
	done := make(chan error, 1)
	go func() { done <- srv.HandshakeContext(t.Context()) }()

	require.NoError(t, tls.Client(cConn, clientCfg).HandshakeContext(t.Context()))
	require.NoError(t, <-done)
	peers := srv.ConnectionState().PeerCertificates
	require.NotEmpty(t, peers)
	require.Equal(t, "client", peers[0].Subject.CommonName)
}

func pemCert(cert tls.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
}

func pemKey(tb testing.TB, cert tls.Certificate) []byte {
	tb.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	require.NoError(tb, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
