// Copyright 2021-2026 ALTESSA SOLUTIONS INC. All rights reserved.
// Use of this source code is governed by license that can be found in
// the LICENSE file.

package tlsproviders

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
)

type mockProvider struct {
	typ    ProviderType
	closed int
}

func (m *mockProvider) Type() ProviderType              { return m.typ }
func (m *mockProvider) TLSConfig() (*tls.Config, error) { return &tls.Config{}, nil } //nolint:gosec
func (m *mockProvider) Close(_ context.Context) error   { m.closed++; return nil }

// valueProvider is a non-comparable provider value: re-registering it must
// not panic on ==.
type valueProvider struct {
	tags []string
}

func (valueProvider) Type() ProviderType              { return ProviderTypeS3 }
func (valueProvider) TLSConfig() (*tls.Config, error) { return &tls.Config{}, nil } //nolint:gosec
func (valueProvider) Close(_ context.Context) error   { return nil }

func TestProviders_Close_ClosesReplaced(t *testing.T) {
	p := &Providers{}
	first := &mockProvider{typ: ProviderTypeFile}
	second := &mockProvider{typ: ProviderTypeFile}
	p.Register(first)
	p.Register(second)
	p.Register(second) // re-registering the active provider replaces nothing

	got, ok := p.Get(ProviderTypeFile)
	require.True(t, ok)
	require.Same(t, second, got)

	p.Close(t.Context(), nil)
	require.Equal(t, 1, first.closed, "a replaced provider is closed")
	require.Equal(t, 1, second.closed, "the active provider is closed once")

	require.NotPanics(t, func() {
		p.Register(valueProvider{})
		p.Register(valueProvider{})
	})
}

// anyFieldProvider has a comparable type whose values may not be (comparing
// two holding slices panics); Close closes its done channel, so a second
// Close panics.
type anyFieldProvider struct {
	v    any
	done chan struct{}
}

func (anyFieldProvider) Type() ProviderType              { return ProviderTypeVault }
func (anyFieldProvider) TLSConfig() (*tls.Config, error) { return &tls.Config{}, nil } //nolint:gosec
func (a anyFieldProvider) Close(_ context.Context) error { close(a.done); return nil }

func TestProviders_NonComparableValueClosedOnce(t *testing.T) {
	p := &Providers{}
	v := anyFieldProvider{v: []string{"x"}, done: make(chan struct{})}
	require.NotPanics(t, func() {
		p.Register(v)
		p.Register(v) // the same value again
		p.Close(t.Context(), nil)
	})
}

func TestProviders_Close_ReRegisteredClosesOnce(t *testing.T) {
	p := &Providers{}
	a := &mockProvider{typ: ProviderTypeFile}
	b := &mockProvider{typ: ProviderTypeFile}
	p.Register(a)
	p.Register(b)
	p.Register(a) // a becomes active again; b is displaced

	p.Close(t.Context(), nil)
	require.Equal(t, 1, a.closed, "a re-registered provider is closed once")
	require.Equal(t, 1, b.closed, "the displaced provider is closed once")
}

func TestProviderType_String(t *testing.T) {
	require.Equal(t, "vault", ProviderTypeVault.String())
}

func TestProviderType_IsValid(t *testing.T) {
	tests := []struct {
		name string
		pt   ProviderType
		want bool
	}{
		{"vault", ProviderTypeVault, true},
		{"file", ProviderTypeFile, true},
		{"letsencrypt", ProviderTypeLetsEncrypt, true},
		{"s3", ProviderTypeS3, true},
		{"unknown", ProviderType("unknown"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.pt.IsValid())
		})
	}
}

func TestAvailableProviders(t *testing.T) {
	require.Len(t, AvailableProviders, 4)
}

func TestProviders_RegisterAndGet(t *testing.T) {
	p := &Providers{}
	mp := &mockProvider{typ: ProviderTypeFile}
	p.Register(mp)

	got, ok := p.Get(ProviderTypeFile)
	require.True(t, ok)
	require.Equal(t, ProviderTypeFile, got.Type())
}

func TestProviders_Get_NotFound(t *testing.T) {
	p := &Providers{}
	_, ok := p.Get(ProviderTypeVault)
	require.False(t, ok)
}

func TestProviders_Close(t *testing.T) {
	p := &Providers{}
	p.Register(&mockProvider{typ: ProviderTypeFile})
	p.Register(&mockProvider{typ: ProviderTypeVault})

	var errCount int
	p.Close(t.Context(), func(_ Provider, _ error) {
		errCount++
	})
	require.Equal(t, 0, errCount)
}

func TestProviders_List(t *testing.T) {
	p := &Providers{}
	p.Register(&mockProvider{typ: ProviderTypeFile})
	p.Register(&mockProvider{typ: ProviderTypeVault})

	count := 0
	for range p.List() {
		count++
	}
	require.Equal(t, 2, count)
}

func BenchmarkProviders_Get(b *testing.B) {
	p := &Providers{}
	p.Register(&mockProvider{typ: ProviderTypeFile})
	for b.Loop() {
		p.Get(ProviderTypeFile)
	}
}
