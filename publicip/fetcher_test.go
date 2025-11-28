// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package publicip

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRoundTripper implements http.RoundTripper for testing
type mockRoundTripper struct {
	statusCode int
	body       string
}

func (m *mockRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: m.statusCode,
		Body:       io.NopCloser(strings.NewReader(m.body)),
	}, nil
}

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
			statusCode: 200,
			body:       "1.2.3.4\n",
			wantIP:     "1.2.3.4",
		},
		{
			name:       "valid IPv6",
			statusCode: 200,
			body:       "2001:0db8:85a3::8a2e:0370:7334",
			wantIP:     "2001:db8:85a3::8a2e:370:7334",
		},
		{
			name:       "IP with whitespace",
			statusCode: 200,
			body:       "  8.8.8.8  \n",
			wantIP:     "8.8.8.8",
		},
		{
			name:       "bad request",
			statusCode: 400,
			body:       "bad request",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			client := &http.Client{
				Transport: &mockRoundTripper{
					statusCode: tt.statusCode,
					body:       tt.body,
				},
			}

			// Execute
			got, err := getPublicIPUsingIPChecker(client, "http://test.example.com")

			// Assert
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, net.ParseIP(tt.wantIP), got)
			}
		})
	}
}

