// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package tlss3

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestS3_TLSConfig_NotYetLoaded pins the guard in TLSConfig against a zero
// value S3 whose tlsConfig was never populated. The public constructor always
// loads a certificate before returning, so this state is only reachable via
// a white-box test constructing the struct directly.
func TestS3_TLSConfig_NotYetLoaded(t *testing.T) {
	t.Parallel()
	p := &S3{}

	_, err := p.TLSConfig()
	require.Error(t, err)
}
