// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlsfile_test

import (
	"testing"

	"github.com/altessa-s/go-tlsutils/internal/testhelpers"

	tlsfile "github.com/altessa-s/go-tlsutils/providers/file"
)

func BenchmarkNewWithCertAndKey(b *testing.B) {
	certPEM, keyPEM, _ := testhelpers.SelfSignedCert(b)
	certPath, keyPath := testhelpers.WriteTempCertFiles(b, certPEM, keyPEM)

	b.ResetTimer()
	for b.Loop() {
		f, err := tlsfile.NewWithCertAndKey(certPath, keyPath, "")
		if err != nil {
			b.Fatal(err)
		}
		f.Close(b.Context())
	}
}

func BenchmarkTLSConfig(b *testing.B) {
	certPEM, keyPEM, _ := testhelpers.SelfSignedCert(b)
	certPath, keyPath := testhelpers.WriteTempCertFiles(b, certPEM, keyPEM)

	f, err := tlsfile.NewWithCertAndKey(certPath, keyPath, "")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close(b.Context())

	b.ResetTimer()
	for b.Loop() {
		_, _ = f.TLSConfig()
	}
}

// BenchmarkTLSConfig_Parallel measures TLSConfig under concurrent readers —
// the shape production traffic hits it in, since every accepted connection
// calls it independently while the watcher may be reloading in the
// background.
func BenchmarkTLSConfig_Parallel(b *testing.B) {
	certPEM, keyPEM, _ := testhelpers.SelfSignedCert(b)
	certPath, keyPath := testhelpers.WriteTempCertFiles(b, certPEM, keyPEM)

	f, err := tlsfile.NewWithCertAndKey(certPath, keyPath, "")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close(b.Context())

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := f.TLSConfig(); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkType(b *testing.B) {
	certPEM, keyPEM, _ := testhelpers.SelfSignedCert(b)
	certPath, keyPath := testhelpers.WriteTempCertFiles(b, certPEM, keyPEM)

	f, err := tlsfile.NewWithCertAndKey(certPath, keyPath, "")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close(b.Context())

	b.ResetTimer()
	for b.Loop() {
		_ = f.Type()
	}
}
