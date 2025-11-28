// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package publicip

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errorReader is a custom reader that always returns an error
type errorReader struct{}

func (e errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("read error")
}

func TestHandleRequest(t *testing.T) {
	tests := []struct {
		name             string
		statusCode       int
		body             string
		useErrorReader   bool
		wantIP           string
		wantErr          bool
		wantErrMsg       string
		wantPermanentErr bool
	}{
		{
			name:       "valid IPv4",
			statusCode: http.StatusOK,
			body:       "192.0.2.1",
			wantIP:     "192.0.2.1",
		},
		{
			name:       "valid IPv4 with leading whitespace",
			statusCode: http.StatusOK,
			body:       "  192.0.2.1",
			wantIP:     "192.0.2.1",
		},
		{
			name:       "valid IPv4 with trailing whitespace",
			statusCode: http.StatusOK,
			body:       "192.0.2.1\n",
			wantIP:     "192.0.2.1",
		},
		{
			name:       "valid IPv4 with leading and trailing whitespace",
			statusCode: http.StatusOK,
			body:       "  \n\t192.0.2.1\n\t  ",
			wantIP:     "192.0.2.1",
		},
		{
			name:       "valid IPv6",
			statusCode: http.StatusOK,
			body:       "2001:db8::1",
			wantIP:     "2001:db8::1",
		},
		{
			name:       "valid IPv6 with whitespace",
			statusCode: http.StatusOK,
			body:       "  2001:db8::1\n",
			wantIP:     "2001:db8::1",
		},
		{
			name:       "valid IPv6 full notation",
			statusCode: http.StatusOK,
			body:       "2001:0db8:0000:0000:0000:0000:0000:0001",
			wantIP:     "2001:db8::1",
		},
		{
			name:             "status 400 returns permanent error",
			statusCode:       http.StatusBadRequest,
			body:             "192.0.2.1",
			wantErr:          true,
			wantErrMsg:       "bad request",
			wantPermanentErr: true,
		},
		{
			name:       "invalid IP address",
			statusCode: http.StatusOK,
			body:       "not.an.ip.address",
			wantErr:    true,
			wantErrMsg: "IP address not valid: not.an.ip.address",
		},
		{
			name:       "empty body",
			statusCode: http.StatusOK,
			body:       "",
			wantErr:    true,
			wantErrMsg: "IP address not valid: ",
		},
		{
			name:       "whitespace only",
			statusCode: http.StatusOK,
			body:       "   \n\t  ",
			wantErr:    true,
			wantErrMsg: "IP address not valid: ",
		},
		{
			name:       "invalid IPv4 out of range",
			statusCode: http.StatusOK,
			body:       "256.256.256.256",
			wantErr:    true,
			wantErrMsg: "IP address not valid: 256.256.256.256",
		},
		{
			name:       "incomplete IPv4",
			statusCode: http.StatusOK,
			body:       "192.0.2",
			wantErr:    true,
			wantErrMsg: "IP address not valid: 192.0.2",
		},
		{
			name:       "text with IP inside",
			statusCode: http.StatusOK,
			body:       "Your IP is: 192.0.2.1",
			wantErr:    true,
			wantErrMsg: "IP address not valid: Your IP is: 192.0.2.1",
		},
		{
			name:       "status 500 with valid IP",
			statusCode: http.StatusInternalServerError,
			body:       "192.0.2.1",
			wantIP:     "192.0.2.1",
		},
		{
			name:       "status 404 with valid IP",
			statusCode: http.StatusNotFound,
			body:       "192.0.2.1",
			wantIP:     "192.0.2.1",
		},
		{
			name:           "failed to read content",
			statusCode:     http.StatusOK,
			useErrorReader: true,
			wantErr:        true,
			wantErrMsg:     "failed to read content: read error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				if tt.useErrorReader {
					// Write header but don't write body, we'll handle it with error reader
					return
				}
				w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client := server.Client()
			if tt.useErrorReader {
				// Use a custom transport that returns a response with an error reader
				client.Transport = &errorTransport{statusCode: tt.statusCode}
			}

			req, err := http.NewRequest("GET", server.URL, nil)
			require.NoError(t, err)

			gotIP, err := handleRequest(client, req)

			if tt.wantErr {
				require.Error(t, err)
				if tt.wantPermanentErr {
					// Check if it's a permanent error from backoff package
					var permanentErr *backoff.PermanentError
					assert.ErrorAs(t, err, &permanentErr)
					// Unwrap to get the actual error message
					assert.ErrorContains(t, permanentErr.Unwrap(), tt.wantErrMsg)
				} else {
					assert.ErrorContains(t, err, tt.wantErrMsg)
				}
				return
			}

			require.NoError(t, err)
			assert.Equal(t, net.ParseIP(tt.wantIP), gotIP)
		})
	}
}

func TestHandleRequest_ClientDoError(t *testing.T) {
	// Test client.Do error by using an invalid URL
	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://invalid-host-that-does-not-exist-12345.com", nil)
	require.NoError(t, err)

	_, err = handleRequest(client, req)
	require.Error(t, err)
	assert.ErrorContains(t, err, "failed to fetch req")
}

// errorTransport is a custom RoundTripper that returns a response with an error reader
type errorTransport struct {
	statusCode int
}

func (t *errorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		Status:     http.StatusText(t.statusCode),
		StatusCode: t.statusCode,
		Body:       io.NopCloser(errorReader{}),
		Header:     make(http.Header),
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
