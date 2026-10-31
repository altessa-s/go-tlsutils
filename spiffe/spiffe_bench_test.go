// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package spiffe_test

import (
	"testing"

	"github.com/altessa-s/go-tlsutils/spiffe"
)

func BenchmarkMTLSServerConfig(b *testing.B) {
	p, err := spiffe.NewProvider(&fakeSource{}, anyAuthorizer())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = p.MTLSServerConfig()
	}
}
