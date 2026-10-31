// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlsvault

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	vaultApi "github.com/hashicorp/vault/api"
)

// TestAttrPool_GetFallbackOnTypeMismatch pins that attrPool.get falls back to
// allocating a fresh slice instead of panicking when the pool yields a value
// of the wrong type. A dedicated pool instance is used (rather than the
// package's shared globalAttrPool) so the test needs no serialization.
func TestAttrPool_GetFallbackOnTypeMismatch(t *testing.T) {
	t.Parallel()
	pool := newAttrPool()
	pool.pool.Put("not a []slog.Attr") // wrong type: forces the type-assertion fallback.

	attrsPtr := pool.get()
	require.NotNil(t, attrsPtr)
	require.Empty(t, *attrsPtr)
}

// ctxCloser implements both vault.AuthMethod and the richer
// Close(context.Context) error that Vault.Close prefers when an AuthMethod
// implements it.
type ctxCloser struct {
	called   bool
	gotCtx   context.Context
	closeErr error
}

func (c *ctxCloser) SetToken(context.Context, *vaultApi.Client) error { return nil }

func (c *ctxCloser) Close(ctx context.Context) error {
	c.called = true
	c.gotCtx = ctx
	return c.closeErr
}

// TestVault_Close_PrefersContextCloser pins that Close passes the provided
// context through to an AuthMethod implementing Close(context.Context) error,
// in preference to the plain io.Closer branch. None of the AuthMethod types
// this package ships today implement that richer interface, so this is only
// reachable via a white-box construction of Vault.
func TestVault_Close_PrefersContextCloser(t *testing.T) {
	t.Parallel()
	cc := &ctxCloser{}
	v := &Vault{authMethod: cc}

	ctx := t.Context()
	require.NoError(t, v.Close(ctx))
	require.True(t, cc.called)
	require.Equal(t, ctx, cc.gotCtx)
}
