// Copyright 2021-2026 ALTESSA SOLUTIONS INC. All rights reserved.
// Use of this source code is governed by license that can be found in
// the LICENSE file.

//go:build unix

package tlsutils_test

import (
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-atlas-core/io/files"

	tlsutils "github.com/altessa-s/go-tlsutils"
)

func TestLoad_RejectsFIFO(t *testing.T) {
	t.Parallel()
	fifo := filepath.Join(t.TempDir(), "key.pem")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	certPath := writeFile(t, "cert.pem", leaf(t, ecKey(t)), 0o644)

	_, err := tlsutils.LoadFromFile(fifo, certPath, "")
	require.ErrorIs(t, err, files.ErrNotRegular)

	_, err = tlsutils.LoadFromFile(fifo, fifo, "")
	require.ErrorIs(t, err, files.ErrNotRegular)

	_, err = tlsutils.LoadFromConcatenatedFile(fifo, "")
	require.ErrorIs(t, err, files.ErrNotRegular)

	_, err = tlsutils.BuildCAPool(false, fifo)
	require.ErrorIs(t, err, files.ErrNotRegular)
}
