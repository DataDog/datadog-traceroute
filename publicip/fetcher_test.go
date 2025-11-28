// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package publicip

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetPublicIPUsingIPChecker(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantIP     string
		wantErr    bool
	}{
		{
			name:       "valid IPv4",
			statusCode: http.StatusOK,
			body:       "192.0.2.1",
			wantIP:     "192.0.2.1",
			wantErr:    false,
		},
		{
			name:       "valid IPv4 with whitespace",
			statusCode: http.StatusOK,
			body:       "  192.0.2.1\n",
			wantIP:     "192.0.2.1",
			wantErr:    false,
		},
		{
			name:       "valid IPv6",
			statusCode: http.StatusOK,
			body:       "2001:db8::1",
			wantIP:     "2001:db8::1",
			wantErr:    false,
		},
		{
			name:       "bad request 400",
			statusCode: http.StatusBadRequest,
			body:       "192.0.2.1",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client := server.Client()
			backoffPolicy := backoff.NewExponentialBackOff()
			backoffPolicy.InitialInterval = 1 * time.Millisecond
			backoffPolicy.MaxInterval = 5 * time.Millisecond

			gotIP, err := getPublicIPUsingIPChecker(client, backoffPolicy, server.URL)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, net.ParseIP(tt.wantIP), gotIP)
		})
	}
}
