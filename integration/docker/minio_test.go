// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

//go:build integration_docker

package docker_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"

	tlss3 "github.com/altessa-s/go-tlsutils/providers/s3"
	tcminio "github.com/testcontainers/testcontainers-go/modules/minio"
)

const (
	// minioImage is Chainguard's MinIO build: the upstream minio/minio and
	// quay.io/minio/minio images are no longer publicly pullable, and the
	// Chainguard free tier publishes only the latest tag.
	minioImage  = "cgr.dev/chainguard/minio:latest"
	minioBucket = "certificates"
	certObject  = "tls/server.crt"
	keyObject   = "tls/server.key"
)

// TestMinIOProvider loads a leaf and chain from MinIO through providers/s3,
// verifies a handshake, then overwrites the objects and waits for the ETag
// poll to serve the new leaf.
func TestMinIOProvider(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)
	t.Parallel()
	ctx := t.Context()

	// The image runs as a non-root user that cannot create /data.
	ctr, err := tcminio.Run(ctx, minioImage, testcontainers.WithCmd("server", "/tmp"))
	testcontainers.CleanupContainer(t, ctr)
	require.NoError(t, err)

	endpoint, err := ctr.ConnectionString(ctx)
	require.NoError(t, err)

	client := s3.New(s3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String("http://" + endpoint),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider(ctr.Username, ctr.Password, ""),
	})
	_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(minioBucket)})
	require.NoError(t, err)

	ca := newTestCA(t)
	roots := x509.NewCertPool()
	roots.AddCert(ca.root)

	first, chainPEM, keyPEM := ca.issueLeaf(t)
	putObject(t, ctx, client, keyObject, keyPEM)
	putObject(t, ctx, client, certObject, chainPEM)

	provider, err := tlss3.New(minioBucket, certObject, keyObject, "",
		tlss3.WithS3Client(client),
		tlss3.WithPollInterval(200*time.Millisecond),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, provider.Close(context.WithoutCancel(ctx))) })

	serverCfg, err := provider.TLSConfig()
	require.NoError(t, err)
	state := handshake(t, ctx, serverCfg, clientConfig(roots))
	requireVerifiedTo(t, state, ca.root)
	require.Equal(t, first.SerialNumber, state.PeerCertificates[0].SerialNumber)
	require.Len(t, state.PeerCertificates, 2, "intermediate missing from the served chain")
	require.True(t, state.PeerCertificates[1].Equal(ca.inter))

	second, chainPEM, keyPEM := ca.issueLeaf(t)
	putObject(t, ctx, client, keyObject, keyPEM)
	putObject(t, ctx, client, certObject, chainPEM)

	require.Eventually(t, func() bool {
		cfg, err := provider.TLSConfig()
		if err != nil {
			return false
		}
		st, err := tryHandshake(ctx, cfg, clientConfig(roots))
		return err == nil && st.PeerCertificates[0].SerialNumber.Cmp(second.SerialNumber) == 0
	}, 15*time.Second, 100*time.Millisecond, "provider did not reload the overwritten certificate")
}

func putObject(tb testing.TB, ctx context.Context, client *s3.Client, key string, body []byte) {
	tb.Helper()
	_, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(minioBucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(body),
	})
	require.NoError(tb, err)
}
