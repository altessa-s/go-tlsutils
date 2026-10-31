// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package spiffe_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-tlsutils/spiffe"
)

// With an authorizer but no reachable Workload API, New fails once the
// context ends instead of returning a provider without an SVID.
func TestNew_UnreachableWorkloadAPI(t *testing.T) {
	t.Parallel()
	sock := "unix://" + filepath.Join(t.TempDir(), "agent.sock")

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	p, err := spiffe.New(ctx,
		spiffe.WithAuthorizer(anyAuthorizer()),
		spiffe.WithAuthorizer(nil), // ignored: keeps the previous authorizer
		spiffe.WithSocketPath(sock),
	)
	require.Error(t, err)
	require.NotErrorIs(t, err, spiffe.ErrNoAuthorizer)
	require.ErrorContains(t, err, "create X509 source")
	require.Nil(t, p)
}

func TestNew_NilAuthorizerOnlyIsRejected(t *testing.T) {
	t.Parallel()
	_, err := spiffe.New(t.Context(), spiffe.WithAuthorizer(nil))
	require.ErrorIs(t, err, spiffe.ErrNoAuthorizer)
}
