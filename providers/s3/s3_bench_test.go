// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlss3_test

import (
	"fmt"
	"testing"
	"time"

	tlss3 "github.com/altessa-s/go-tlsutils/providers/s3"
)

func BenchmarkNew(b *testing.B) {
	client, _, _ := newMockClient(b)

	b.ResetTimer()
	for b.Loop() {
		p, err := tlss3.New("my-bucket", "certs/server.crt", "certs/server.key", "",
			tlss3.WithS3Client(client),
			tlss3.WithPollInterval(time.Hour),
		)
		if err != nil {
			b.Fatal(err)
		}
		p.Close(b.Context())
	}
}

func BenchmarkTLSConfig(b *testing.B) {
	client, _, _ := newMockClient(b)

	p, err := tlss3.New("my-bucket", "certs/server.crt", "certs/server.key", "",
		tlss3.WithS3Client(client),
		tlss3.WithPollInterval(time.Hour),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer p.Close(b.Context())

	b.ResetTimer()
	for b.Loop() {
		_, _ = p.TLSConfig()
	}
}

// BenchmarkTLSConfig_Parallel exercises the provider's real hot path: readers
// calling TLSConfig concurrently with a background goroutine driving reloads,
// so TLSConfig's RLock contends with loadCertificate's Lock.
func BenchmarkTLSConfig_Parallel(b *testing.B) {
	client, certPEM, _ := newMockClient(b)
	notify := make(chan struct{}, 1)

	p, err := tlss3.New("my-bucket", "certs/server.crt", "certs/server.key", "",
		tlss3.WithS3Client(client),
		tlss3.WithPollInterval(time.Millisecond),
		tlss3.WithReloadNotifyChan(notify),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer p.Close(b.Context())
	<-notify // drain the initial load notification

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			client.SetObject("certs/server.crt", &mockObject{data: certPEM, etag: fmt.Sprintf(`"etag-%d"`, i)})
			select {
			case <-notify:
			case <-stop:
				return
			}
		}
	}()

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = p.TLSConfig()
		}
	})
}

func BenchmarkType(b *testing.B) {
	client, _, _ := newMockClient(b)

	p, err := tlss3.New("my-bucket", "certs/server.crt", "certs/server.key", "",
		tlss3.WithS3Client(client),
		tlss3.WithPollInterval(time.Hour),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer p.Close(b.Context())

	b.ResetTimer()
	for b.Loop() {
		_ = p.Type()
	}
}
