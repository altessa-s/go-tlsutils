// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlsfile_test

import (
	"context"
	"crypto/tls"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-tlsutils/internal/testhelpers"

	tlsproviders "github.com/altessa-s/go-tlsutils/providers"
	tlsfile "github.com/altessa-s/go-tlsutils/providers/file"
)

func TestNewWithCertAndKey_EmptyCertFile(t *testing.T) {
	_, err := tlsfile.NewWithCertAndKey("", "key.pem", "")
	require.Error(t, err)
}

func TestNewWithCertAndKey_EmptyKeyFile(t *testing.T) {
	_, err := tlsfile.NewWithCertAndKey("cert.pem", "", "")
	require.Error(t, err)
}

func TestNewWithCertAndKey_NonexistentFiles(t *testing.T) {
	_, err := tlsfile.NewWithCertAndKey("/nonexistent/cert.pem", "/nonexistent/key.pem", "")
	require.Error(t, err)
}

func TestNewWithCertAndKey_ValidCert(t *testing.T) {
	certPEM, keyPEM, _ := testhelpers.SelfSignedCert(t)
	certPath, keyPath := testhelpers.WriteTempCertFiles(t, certPEM, keyPEM)

	f, err := tlsfile.NewWithCertAndKey(certPath, keyPath, "")
	require.NoError(t, err)
	defer f.Close(t.Context())

	require.Equal(t, tlsproviders.ProviderTypeFile, f.Type())
}

// TestNewWithCertAndKey_ChecksKeyPermissions pins that the 0600 limit applies
// to the key file, not the certificate.
func TestNewWithCertAndKey_ChecksKeyPermissions(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM, _ := testhelpers.SelfSignedCert(t)
	certPath, keyPath := testhelpers.WriteTempCertFiles(t, certPEM, keyPEM)

	require.NoError(t, os.Chmod(certPath, 0o644))
	f, err := tlsfile.NewWithCertAndKey(certPath, keyPath, "")
	require.NoError(t, err, "a world-readable certificate with a 0600 key loads")
	require.NoError(t, f.Close(t.Context()))

	require.NoError(t, os.Chmod(keyPath, 0o644))
	_, err = tlsfile.NewWithCertAndKey(certPath, keyPath, "")
	require.ErrorContains(t, err, "insecure permissions", "a world-readable key is rejected")
}

func TestFile_TLSConfig(t *testing.T) {
	certPEM, keyPEM, _ := testhelpers.SelfSignedCert(t)
	certPath, keyPath := testhelpers.WriteTempCertFiles(t, certPEM, keyPEM)

	f, err := tlsfile.NewWithCertAndKey(certPath, keyPath, "")
	require.NoError(t, err)
	defer f.Close(t.Context())

	config, err := f.TLSConfig()
	require.NoError(t, err)
	require.NotNil(t, config)
	require.NotEmpty(t, config.Certificates)
}

func TestFile_TLSConfig_ReturnsCopy(t *testing.T) {
	certPEM, keyPEM, _ := testhelpers.SelfSignedCert(t)
	certPath, keyPath := testhelpers.WriteTempCertFiles(t, certPEM, keyPEM)

	f, err := tlsfile.NewWithCertAndKey(certPath, keyPath, "")
	require.NoError(t, err)
	defer f.Close(t.Context())

	cfg1, _ := f.TLSConfig()
	cfg2, _ := f.TLSConfig()

	// Modifying one should not affect the other
	cfg1.ServerName = "modified"
	require.NotEqual(t, "modified", cfg2.ServerName)
}

// TestFile_GetClientCertificate_ReflectsReload pins that, like TLSConfig,
// GetClientCertificate serves the rewritten certificate once the watcher
// reloads it rather than the one loaded at construction.
func TestFile_GetClientCertificate_ReflectsReload(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM, _ := testhelpers.SelfSignedCert(t)
	certPath, keyPath := testhelpers.WriteTempCertFiles(t, certPEM, keyPEM)
	notify := make(chan struct{}, 1)

	f, err := tlsfile.NewWithCertAndKey(certPath, keyPath, "",
		tlsfile.WithEnableWatcher(),
		tlsfile.WithReloadNotifyChan(notify),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close(t.Context()) })
	<-notify // initial load

	before, err := f.GetClientCertificate(&tls.CertificateRequestInfo{})
	require.NoError(t, err)

	newCertPEM, newKeyPEM, _ := testhelpers.SelfSignedCert(t)
	require.NoError(t, os.WriteFile(keyPath, newKeyPEM, 0o600))
	require.NoError(t, os.WriteFile(certPath, newCertPEM, 0o600))

	select {
	case <-notify:
	case <-time.After(10 * time.Second):
		require.Fail(t, "timeout waiting for certificate reload")
	}

	after, err := f.GetClientCertificate(&tls.CertificateRequestInfo{})
	require.NoError(t, err)
	require.NotEqual(t, before.Certificate, after.Certificate,
		"GetClientCertificate must serve the rewritten certificate after reload")
}

func TestFile_Close(t *testing.T) {
	certPEM, keyPEM, _ := testhelpers.SelfSignedCert(t)
	certPath, keyPath := testhelpers.WriteTempCertFiles(t, certPEM, keyPEM)

	f, err := tlsfile.NewWithCertAndKey(certPath, keyPath, "")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	require.NoError(t, f.Close(ctx))
}

func TestFile_Type(t *testing.T) {
	certPEM, keyPEM, _ := testhelpers.SelfSignedCert(t)
	certPath, keyPath := testhelpers.WriteTempCertFiles(t, certPEM, keyPEM)

	f, err := tlsfile.NewWithCertAndKey(certPath, keyPath, "")
	require.NoError(t, err)
	defer f.Close(t.Context())

	require.Equal(t, tlsproviders.ProviderTypeFile, f.Type())
}

func TestNewWithCertAndKey_InvalidParams(t *testing.T) {
	tests := []struct {
		name     string
		certFile string
		keyFile  string
		wantErr  bool
	}{
		{"both empty", "", "", true},
		{"cert empty", "", "key.pem", true},
		{"key empty", "cert.pem", "", true},
		{"nonexistent", "/tmp/nonexistent.pem", "/tmp/nonexistent.key", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tlsfile.NewWithCertAndKey(tt.certFile, tt.keyFile, "")
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
