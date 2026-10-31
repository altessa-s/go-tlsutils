// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlsfile_test

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-tlsutils/internal/testhelpers"

	tlsfile "github.com/altessa-s/go-tlsutils/providers/file"
)

// TestFile_ReloadServesNewCertificate pins the watcher reload path end to
// end: rewriting the cert and key files on disk notifies the reload channel
// and the next TLSConfig call serves the rewritten certificate, not the one
// loaded at construction.
func TestFile_ReloadServesNewCertificate(t *testing.T) {
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

	before, err := f.TLSConfig()
	require.NoError(t, err)

	newCertPEM, newKeyPEM, _ := testhelpers.SelfSignedCert(t)
	require.NoError(t, os.WriteFile(keyPath, newKeyPEM, 0o600))
	require.NoError(t, os.WriteFile(certPath, newCertPEM, 0o600))

	select {
	case <-notify:
	case <-time.After(10 * time.Second):
		require.Fail(t, "timeout waiting for certificate reload")
	}

	after, err := f.TLSConfig()
	require.NoError(t, err)
	require.False(t,
		bytes.Equal(before.Certificates[0].Certificate[0], after.Certificates[0].Certificate[0]),
		"the rewritten certificate must be served after the watcher reloads it")
}

// TestFile_ReloadFailureKeepsOldConfig pins that a reload which fails to
// parse (corrupted key file) leaves the previously loaded certificate in
// place, and that the watcher keeps running afterward so a subsequent valid
// rewrite still reloads normally.
func TestFile_ReloadFailureKeepsOldConfig(t *testing.T) {
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

	original, err := f.TLSConfig()
	require.NoError(t, err)
	originalCert := original.Certificates[0].Certificate[0]

	// Corrupt the key file. The watcher picks up the write, loadCertificate
	// fails to parse it, and the previously published config must survive.
	require.NoError(t, os.WriteFile(keyPath, []byte("not a key"), 0o600))

	require.Never(t, func() bool {
		cfg, cerr := f.TLSConfig()
		return cerr != nil || !bytes.Equal(cfg.Certificates[0].Certificate[0], originalCert)
	}, 500*time.Millisecond, 25*time.Millisecond,
		"a failed reload must not replace or clear the previously served certificate")

	// The watcher must still be alive after the failed reload: a valid
	// rewrite reloads normally.
	newCertPEM, newKeyPEM, _ := testhelpers.SelfSignedCert(t)
	require.NoError(t, os.WriteFile(keyPath, newKeyPEM, 0o600))
	require.NoError(t, os.WriteFile(certPath, newCertPEM, 0o600))

	select {
	case <-notify:
	case <-time.After(10 * time.Second):
		require.Fail(t, "timeout waiting for the recovery reload after a failed reload")
	}

	recovered, err := f.TLSConfig()
	require.NoError(t, err)
	require.False(t, bytes.Equal(recovered.Certificates[0].Certificate[0], originalCert),
		"the certificate must update once the watcher recovers with a valid rewrite")
}

// TestFile_Close_WatcherAndExpiredContext pins Close's timeout path: with the
// watcher enabled and a context whose deadline has already passed, Close
// must give up waiting for the watcher goroutine and report the context
// error instead of blocking.
func TestFile_Close_WatcherAndExpiredContext(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM, _ := testhelpers.SelfSignedCert(t)
	certPath, keyPath := testhelpers.WriteTempCertFiles(t, certPEM, keyPEM)

	f, err := tlsfile.NewWithCertAndKey(certPath, keyPath, "", tlsfile.WithEnableWatcher())
	require.NoError(t, err)

	expired, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Hour))
	defer cancel()

	err = f.Close(expired)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
