// Copyright 2021-2026 ALTESSA SOLUTIONS INC. All rights reserved.
// Use of this source code is governed by license that can be found in
// the LICENSE file.

package tlsproviders

import (
	"context"
	"iter"
	"maps"
	"reflect"
	"slices"
	"sync"
)

// ProviderType identifies the type of TLS certificate provider.
// Use the predefined constants for supported provider types.
type ProviderType string

const (
	// ProviderTypeVault is the Vault-based certificate provider.
	ProviderTypeVault ProviderType = "vault"
	// ProviderTypeFile is the file-based certificate provider.
	ProviderTypeFile ProviderType = "file"
	// ProviderTypeLetsEncrypt is the Let's Encrypt certificate provider.
	ProviderTypeLetsEncrypt ProviderType = "letsencrypt"
	// ProviderTypeS3 is the S3-based certificate provider.
	ProviderTypeS3 ProviderType = "s3"
)

// String returns the string representation of the provider type.
// Implements the fmt.Stringer interface.
//
// Example:
//
//	fmt.Println(ProviderTypeVault.String()) // "vault"
func (t ProviderType) String() string {
	return string(t)
}

// IsValid returns true if the provider type is a supported provider.
// Used for validating provider type configurations.
//
// Example:
//
//	if !providerType.IsValid() {
//		return errors.New("unsupported provider type")
//	}
func (t ProviderType) IsValid() bool {
	switch t {
	case ProviderTypeVault, ProviderTypeFile, ProviderTypeLetsEncrypt, ProviderTypeS3:
		return true
	}
	return false
}

// AvailableProviders is the list of all available provider types.
// Use this to enumerate or display supported provider types.
var AvailableProviders = []ProviderType{
	ProviderTypeVault,
	ProviderTypeFile,
	ProviderTypeLetsEncrypt,
	ProviderTypeS3,
}

// Providers is a collection of TLS providers.
// It provides thread-safe registration and lookup of providers by type.
type Providers struct {
	mu        sync.RWMutex
	providers map[ProviderType]Provider
	// replaced holds providers displaced by Register; Close still closes
	// them so their watchers and pollers do not outlive the collection.
	// Invariant: no provider appears twice in replaced or in both replaced
	// and providers, so Close closes each provider once.
	replaced []Provider
}

// Register registers a TLS provider with the provider collection.
// The provider's type is used as the registry key. A provider already
// registered under the same type is replaced: Get and List no longer return
// it, and [Providers.Close] still closes it once. That requires a comparable
// provider value (a pointer, as every provider in this module is); a replaced
// non-comparable value is not closed and stays its owner's to close.
//
// Example:
//
//	providers.Register(fileProvider)
func (p *Providers) Register(provider Provider) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.providers == nil {
		p.providers = make(map[ProviderType]Provider)
	}
	// Only a provider with a comparable identity is kept: a non-comparable
	// value cannot be told apart from the same value registered again, and
	// closing it twice is worse than leaving it to its owner.
	if old, ok := p.providers[provider.Type()]; ok && hasIdentity(old) && !sameProvider(old, provider) {
		p.replaced = append(p.replaced, old)
	}
	// A provider registered again is active, not displaced.
	p.replaced = slices.DeleteFunc(p.replaced, func(r Provider) bool { return sameProvider(r, provider) })
	p.providers[provider.Type()] = provider
}

// sameProvider reports whether a and b are the same provider value. Values
// that cannot be compared (a non-comparable type, or an interface field
// holding a slice or map) are never the same, which avoids a panic on ==.
func sameProvider(a, b Provider) bool {
	return reflect.TypeOf(a) == reflect.TypeOf(b) && hasIdentity(a) && hasIdentity(b) && a == b
}

// hasIdentity reports whether p can be compared with == without panicking
// and equals itself (a value holding NaN does not), so it can be recognized
// when registered again.
func hasIdentity(p Provider) bool {
	return reflect.ValueOf(p).Comparable() && p == p //nolint:gocritic // self-comparison rejects NaN-holding values
}

// Get returns a provider by type.
// Returns false if the provider type is not registered.
//
// Example:
//
//	prov, ok := providers.Get(ProviderTypeFile)
//	if ok {
//		config, _ := prov.TLSConfig()
//	}
func (p *Providers) Get(t ProviderType) (Provider, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	provider, ok := p.providers[t]
	return provider, ok
}

// Close closes all registered providers, and those replaced by Register, with
// the given context.
// The context controls the graceful shutdown timeout for each provider.
// The errCallback is invoked for each provider that returns an error.
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//	providers.Close(ctx, func(p Provider, err error) {
//		log.Printf("error closing %s: %v", p.Type(), err)
//	})
func (p *Providers) Close(ctx context.Context, errCallback func(p Provider, err error)) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, provider := range slices.Concat(p.replaced, slices.Collect(maps.Values(p.providers))) {
		if err := provider.Close(ctx); err != nil && errCallback != nil {
			errCallback(provider, err)
		}
	}
}

// List returns an iterator over all registered providers.
// The order of providers is not guaranteed.
//
// Example:
//
//	for prov := range providers.List() {
//		fmt.Println(prov.Type())
//	}
func (p *Providers) List() iter.Seq[Provider] {
	return func(yield func(Provider) bool) {
		p.mu.RLock()
		defer p.mu.RUnlock()

		for _, prov := range p.providers {
			if !yield(prov) {
				return
			}
		}
	}
}
