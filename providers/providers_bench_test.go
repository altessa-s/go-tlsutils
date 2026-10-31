// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlsproviders

import "testing"

// BenchmarkProviders_Get_Parallel measures Get under concurrent readers, the
// shape production traffic hits it in: every accepted connection looks up its
// provider independently while Register may run concurrently in the background.
func BenchmarkProviders_Get_Parallel(b *testing.B) {
	p := &Providers{}
	p.Register(&mockProvider{typ: ProviderTypeFile})

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			p.Get(ProviderTypeFile)
		}
	})
}
