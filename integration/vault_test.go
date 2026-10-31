// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

//go:build integration

package integration_test

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-tlsutils/internal/testhelpers"
	"github.com/altessa-s/go-tlsutils/ocsp"
	tlsvault "github.com/altessa-s/go-tlsutils/providers/vault"
)

// fakePKI emulates the Vault PKI sign endpoint: it signs the submitted CSR
// with issuer and returns the issuing CA alongside the certificate.
type fakePKI struct {
	issuer  *testhelpers.CA
	ocspURL string
	signs   atomic.Int32
}

func (f *fakePKI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CSR string `json:"csr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	block, _ := pem.Decode([]byte(body.CSR))
	if block == nil {
		http.Error(w, "missing CSR", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		OCSPServer:   []string{f.ocspURL},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.issuer.Cert, csr.PublicKey, f.issuer.Key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	f.signs.Add(1)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
		"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		"issuing_ca":  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.issuer.Cert.Raw})),
	}})
}

// TestVaultProvider_IssuedCertificateHandshake proves that the Vault provider
// obtains a certificate from the PKI sign endpoint and serves it with the
// issuing CA in the chain, so a client trusting only the root verifies it,
// and that the served certificate is stapled.
func TestVaultProvider_IssuedCertificateHandshake(t *testing.T) {
	t.Parallel()
	const vaultServerName = "svc.example.com"

	pki := newTestPKI(t)
	resp := newResponder(t, pki.inter, 0)
	fake := &fakePKI{issuer: pki.inter, ocspURL: resp.URL()}
	mux := http.NewServeMux()
	mux.Handle("PUT /v1/pki/sign/web", fake)
	vaultSrv := httptest.NewServer(mux)
	t.Cleanup(vaultSrv.Close)

	prov, err := tlsvault.New(
		tlsvault.WithEndpoint(vaultSrv.URL),
		tlsvault.WithStaticToken("s.integration"),
		tlsvault.WithRole("web"),
		tlsvault.WithCommonName(vaultServerName),
		tlsvault.WithSubjectAlternativeNames(vaultServerName),
		tlsvault.WithOcspStapler(newStapler(ocsp.FailureModeHard)),
		tlsvault.WithLogger(discardLogger),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = prov.Close(t.Context()) })

	serverCfg, err := prov.TLSConfig()
	require.NoError(t, err)
	clientCfg := pki.clientConfig()
	clientCfg.ServerName = vaultServerName

	state, err := handshake(t, serverCfg, clientCfg)
	require.NoError(t, err)
	require.NotEmpty(t, state.VerifiedChains, "the client must verify the issued chain against the root pool")
	require.Len(t, state.PeerCertificates, 2, "the issuing CA is appended to the chain")
	require.Equal(t, vaultServerName, state.PeerCertificates[0].Subject.CommonName)
	require.True(t, state.PeerCertificates[1].Equal(pki.inter.Cert))
	requireGoodStaple(t, state, pki.inter.Cert)

	// The issued certificate is cached: a second handshake does not sign again.
	_, err = handshake(t, serverCfg, clientCfg)
	require.NoError(t, err)
	require.Equal(t, int32(1), fake.signs.Load())
}
