// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-tlsutils/ocsp"

	tlss3 "github.com/altessa-s/go-tlsutils/providers/s3"
)

var errNoSuchKey = errors.New("fake s3: no such key")

// fakeS3 is an in-memory bucket implementing [tlss3.S3API]. Every put gives
// the object a fresh ETag.
type fakeS3 struct {
	bucket string

	mu      sync.Mutex
	version int
	objects map[string]fakeObject
}

type fakeObject struct {
	body []byte
	etag string
}

var _ tlss3.S3API = (*fakeS3)(nil)

func newFakeS3(bucket string) *fakeS3 {
	return &fakeS3{bucket: bucket, objects: make(map[string]fakeObject)}
}

// put stores every object under one lock, so a poll never sees half an
// update.
func (f *fakeS3) put(objects map[string][]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for key, body := range objects {
		f.version++
		f.objects[key] = fakeObject{body: bytes.Clone(body), etag: strconv.Quote(strconv.Itoa(f.version))}
	}
}

func (f *fakeS3) lookup(bucket, key *string) (fakeObject, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.objects[aws.ToString(key)]
	if !ok || aws.ToString(bucket) != f.bucket {
		return fakeObject{}, errNoSuchKey
	}
	return obj, nil
}

func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	obj, err := f.lookup(in.Bucket, in.Key)
	if err != nil {
		return nil, err
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(obj.body)), ETag: aws.String(obj.etag)}, nil
}

func (f *fakeS3) HeadObject(_ context.Context, in *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	obj, err := f.lookup(in.Bucket, in.Key)
	if err != nil {
		return nil, err
	}
	return &s3.HeadObjectOutput{ETag: aws.String(obj.etag)}, nil
}

// TestS3Provider_StapledHandshakeAndReload proves that the S3 provider,
// reading through the S3API port, serves a stapled, verifiable chain, and
// that an ETag change picked up by polling swaps in the new leaf.
func TestS3Provider_StapledHandshakeAndReload(t *testing.T) {
	t.Parallel()
	const (
		bucket  = "certs"
		certKey = "tls/server.crt"
		keyKey  = "tls/server.key"
	)

	pki := newTestPKI(t)
	resp := newResponder(t, pki.inter, 0)
	oldLeaf := pki.issueLeaf(t, resp.URL())
	newLeaf := pki.issueLeaf(t, resp.URL())

	store := newFakeS3(bucket)
	store.put(map[string][]byte{certKey: chainPEM(oldLeaf), keyKey: keyPEM(t, oldLeaf)})

	notify := make(chan struct{}, 1)
	prov, err := tlss3.New(bucket, certKey, keyKey, "",
		tlss3.WithS3Client(store),
		tlss3.WithPollInterval(20*time.Millisecond),
		tlss3.WithReloadNotifyChan(notify),
		tlss3.WithOcspStapler(newStapler(ocsp.FailureModeHard)),
		tlss3.WithLogger(discardLogger),
		tlss3.WithContext(t.Context()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = prov.Close(t.Context()) })
	waitNotify(t, notify, "the initial load signals the channel")

	serverCfg, err := prov.TLSConfig()
	require.NoError(t, err)
	state, err := handshake(t, serverCfg, pki.clientConfig())
	require.NoError(t, err)
	require.NotEmpty(t, state.VerifiedChains)
	require.True(t, state.PeerCertificates[0].Equal(oldLeaf.Leaf))
	requireGoodStaple(t, state, pki.inter.Cert)

	store.put(map[string][]byte{certKey: chainPEM(newLeaf), keyKey: keyPEM(t, newLeaf)})
	waitNotify(t, notify, "an ETag change must trigger a reload")

	serverCfg, err = prov.TLSConfig()
	require.NoError(t, err)
	state, err = handshake(t, serverCfg, pki.clientConfig())
	require.NoError(t, err)
	require.True(t, state.PeerCertificates[0].Equal(newLeaf.Leaf), "the reloaded config must serve the new leaf")
	requireGoodStaple(t, state, pki.inter.Cert)
	require.Equal(t, int32(2), resp.requests.Load(), "one OCSP fetch per leaf")
}
