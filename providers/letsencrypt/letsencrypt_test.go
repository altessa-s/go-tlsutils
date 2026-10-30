// Copyright 2021-2026 ALTESSA SOLUTIONS INC. All rights reserved.
// Use of this source code is governed by license that can be found in
// the LICENSE file.

package tlsletsencrypt

import (
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestListenAddr(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
	}{
		{"", ":http"},
		{":80", ":80"},
		{":8080", ":8080"},
		{"0.0.0.0:80", "0.0.0.0:80"},
		{"127.0.0.1:8081", "127.0.0.1:8081"},
		{"127.0.0.1", "127.0.0.1:http"},
		{"127.0.0.1:", "127.0.0.1:http"},
		{"[::]:80", "[::]:80"},
		{"[::]", "[::]:http"},
		{"::", "[::]:http"},
	}

	for _, tt := range tests {
		require.Equal(t, tt.want, listenAddr(tt.in), tt.in)
	}
}

func TestStartHTTPServerWithContext_NilContext(t *testing.T) {
	le := &LetsEncrypt{opts: &options{logger: slog.New(slog.DiscardHandler)}}
	require.Error(t, le.StartHTTPServerWithContext(nil, ":80", nil))
}

func TestStartHTTPServerWithContext_AlreadyStarted(t *testing.T) {
	le := &LetsEncrypt{opts: &options{logger: slog.New(slog.DiscardHandler)}}
	le.mu.Lock()
	le.httpSrv = &http.Server{}
	le.mu.Unlock()

	require.Error(t, le.StartHTTPServerWithContext(t.Context(), ":80", nil))
}
