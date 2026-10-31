// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package certconfig_test

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-tlsutils/internal/testhelpers"
	"github.com/altessa-s/go-tlsutils/providers/internal/certconfig"
	"github.com/altessa-s/go-tlsutils/providers/internal/staplertest"
)

func TestBuild(t *testing.T) {
	t.Parallel()
	_, _, cert := testhelpers.SelfSignedCert(t)
	logger := slog.New(slog.DiscardHandler)

	plain := certconfig.Build(t.Context(), &cert, nil, logger)
	require.Len(t, plain.Certificates, 1, "without a stapler the certificate stays static")
	require.Nil(t, plain.GetCertificate)

	stapler := &staplertest.CountingStapler{}
	stapled := certconfig.Build(t.Context(), &cert, stapler, logger)
	require.Empty(t, stapled.Certificates, "stapling moves the certificate into GetCertificate")
	staplertest.Handshake(t, stapled)
	require.Equal(t, int32(1), stapler.Calls())
}

func TestNotify(t *testing.T) {
	t.Parallel()
	require.NotPanics(t, func() { certconfig.Notify(nil) })

	ch := make(chan struct{}, 1)
	certconfig.Notify(ch)
	certconfig.Notify(ch) // full: must not block
	require.Len(t, ch, 1)
}
