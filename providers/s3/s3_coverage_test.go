// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlss3_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-tlsutils/internal/testhelpers"

	tlss3 "github.com/altessa-s/go-tlsutils/providers/s3"
)

// SetGetErr toggles the error GetObject returns, letting a test fail a
// reload's download after the provider has already loaded successfully once.
func (m *mockS3Client) SetGetErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getErr = err
}

// headErrClient fails HeadObject for exactly one object key, leaving
// GetObject and HeadObject for every other key untouched.
type headErrClient struct {
	*mockS3Client
	failKey string
}

func (m *headErrClient) HeadObject(ctx context.Context, input *s3.HeadObjectInput, opts ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if aws.ToString(input.Key) == m.failKey {
		return nil, errors.New("simulated head failure")
	}
	return m.mockS3Client.HeadObject(ctx, input, opts...)
}

// errBody is an io.ReadCloser whose Read always fails, exercising the
// io.ReadAll error path in downloadObject.
type errBody struct{}

func (errBody) Read([]byte) (int, error) { return 0, errors.New("simulated body read failure") }
func (errBody) Close() error             { return nil }

// bodyErrClient returns a body that fails to read.
type bodyErrClient struct{}

func (bodyErrClient) GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return &s3.GetObjectOutput{Body: errBody{}, ETag: aws.String(`"etag"`)}, nil
}

func (bodyErrClient) HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	return &s3.HeadObjectOutput{ETag: aws.String(`"etag"`)}, nil
}

// zeroReader streams an unbounded sequence of zero bytes, letting a test
// simulate an oversized S3 object without allocating the bytes up front.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// oversizedBodyLen exceeds the provider's undocumented-but-fixed 10 MiB
// object size cap enforced by downloadObject.
const oversizedBodyLen = 10<<20 + 1024

// oversizedBodyClient returns a body larger than the provider's size cap.
type oversizedBodyClient struct{}

func (oversizedBodyClient) GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return &s3.GetObjectOutput{
		Body: io.NopCloser(io.LimitReader(zeroReader{}, oversizedBodyLen)),
		ETag: aws.String(`"etag"`),
	}, nil
}

func (oversizedBodyClient) HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	return &s3.HeadObjectOutput{ETag: aws.String(`"etag"`)}, nil
}

// TestNew_DefaultS3ClientError forces awsconfig.LoadDefaultConfig to fail by
// pointing the shared config file at a directory, pinning that New wraps and
// surfaces the default client construction error instead of panicking or
// masking it. t.Setenv forbids t.Parallel, so this test runs serially.
func TestNew_DefaultS3ClientError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", dir)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", dir)

	_, err := tlss3.New("my-bucket", "certs/server.crt", "certs/server.key", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "creating default S3 client")
}

// TestNew_KeyDownloadError pins that a missing private key object surfaces a
// "downloading private key" error even though the certificate downloaded fine.
func TestNew_KeyDownloadError(t *testing.T) {
	t.Parallel()
	certPEM, _, _ := testhelpers.SelfSignedCert(t)
	client := &mockS3Client{
		objects: map[string]*mockObject{
			"certs/server.crt": {data: certPEM, etag: `"etag-cert"`},
		},
	}

	_, err := tlss3.New("my-bucket", "certs/server.crt", "certs/server.key", "", tlss3.WithS3Client(client))
	require.Error(t, err)
	require.Contains(t, err.Error(), "downloading private key")
}

// TestNew_ParseCertificateError pins that a syntactically invalid key, paired
// with a valid certificate download, surfaces a "parsing certificate" error.
func TestNew_ParseCertificateError(t *testing.T) {
	t.Parallel()
	certPEM, _, _ := testhelpers.SelfSignedCert(t)
	client := &mockS3Client{
		objects: map[string]*mockObject{
			"certs/server.crt": {data: certPEM, etag: `"etag-cert"`},
			"certs/server.key": {data: []byte("not a valid key"), etag: `"etag-key"`},
		},
	}

	_, err := tlss3.New("my-bucket", "certs/server.crt", "certs/server.key", "", tlss3.WithS3Client(client))
	require.Error(t, err)
	require.Contains(t, err.Error(), "parsing certificate")
}

// TestNew_CertBodyReadError pins that a GetObject body that fails mid-read
// surfaces the read error instead of being swallowed.
func TestNew_CertBodyReadError(t *testing.T) {
	t.Parallel()
	_, err := tlss3.New("my-bucket", "certs/server.crt", "certs/server.key", "", tlss3.WithS3Client(bodyErrClient{}))
	require.Error(t, err)
}

// TestNew_DownloadExceedsSizeCap pins that an object larger than the
// provider's size cap is rejected rather than read fully into memory.
func TestNew_DownloadExceedsSizeCap(t *testing.T) {
	t.Parallel()
	_, err := tlss3.New("my-bucket", "certs/server.crt", "certs/server.key", "", tlss3.WithS3Client(oversizedBodyClient{}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds")
}

// TestS3_PollCertHeadError_NoReload pins that a HeadObject failure on the
// certificate key during polling is logged and skipped, without triggering a
// reload.
func TestS3_PollCertHeadError_NoReload(t *testing.T) {
	t.Parallel()
	client, _, _ := newMockClient(t)
	hc := &headErrClient{mockS3Client: client, failKey: "certs/server.crt"}
	notify := make(chan struct{}, 4)

	p, err := tlss3.New("my-bucket", "certs/server.crt", "certs/server.key", "",
		tlss3.WithS3Client(hc),
		tlss3.WithPollInterval(20*time.Millisecond),
		tlss3.WithReloadNotifyChan(notify),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close(t.Context()) })

	select {
	case <-notify:
	case <-time.After(time.Second):
		require.Fail(t, "timeout waiting for initial notification")
	}

	select {
	case <-notify:
		require.Fail(t, "a failed ETag check for the certificate must not trigger a reload")
	case <-time.After(150 * time.Millisecond):
	}
}

// TestS3_PollKeyHeadError_NoReload pins that a HeadObject failure on the
// private key during polling is logged and skipped, without triggering a
// reload. It also exercises the branch where the certificate ETag check
// succeeds but the key ETag check fails.
func TestS3_PollKeyHeadError_NoReload(t *testing.T) {
	t.Parallel()
	client, _, _ := newMockClient(t)
	hc := &headErrClient{mockS3Client: client, failKey: "certs/server.key"}
	notify := make(chan struct{}, 4)

	p, err := tlss3.New("my-bucket", "certs/server.crt", "certs/server.key", "",
		tlss3.WithS3Client(hc),
		tlss3.WithPollInterval(20*time.Millisecond),
		tlss3.WithReloadNotifyChan(notify),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close(t.Context()) })

	select {
	case <-notify:
	case <-time.After(time.Second):
		require.Fail(t, "timeout waiting for initial notification")
	}

	select {
	case <-notify:
		require.Fail(t, "a failed ETag check for the private key must not trigger a reload")
	case <-time.After(150 * time.Millisecond):
	}
}

// TestS3_ReloadFailureKeepsOldConfig pins that a reload triggered by a
// detected ETag change, which then fails to download, leaves the previously
// published TLS config untouched.
func TestS3_ReloadFailureKeepsOldConfig(t *testing.T) {
	t.Parallel()
	client, certPEM, _ := newMockClient(t)
	notify := make(chan struct{}, 4)

	p, err := tlss3.New("my-bucket", "certs/server.crt", "certs/server.key", "",
		tlss3.WithS3Client(client),
		tlss3.WithPollInterval(20*time.Millisecond),
		tlss3.WithReloadNotifyChan(notify),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close(t.Context()) })

	select {
	case <-notify:
	case <-time.After(time.Second):
		require.Fail(t, "timeout waiting for initial notification")
	}

	oldCfg, err := p.TLSConfig()
	require.NoError(t, err)

	// A new ETag makes checkForChanges attempt a reload, but the download
	// itself now fails: the stale config must survive the failed reload.
	client.SetGetErr(errors.New("simulated transient GetObject failure"))
	client.SetObject("certs/server.crt", &mockObject{data: certPEM, etag: `"etag-cert-2"`})

	select {
	case <-notify:
		require.Fail(t, "a failed reload must not publish a new config")
	case <-time.After(200 * time.Millisecond):
	}

	newCfg, err := p.TLSConfig()
	require.NoError(t, err)
	require.Equal(t, oldCfg.Certificates[0].Certificate, newCfg.Certificates[0].Certificate,
		"the previously loaded certificate must be retained after a failed reload")
}
