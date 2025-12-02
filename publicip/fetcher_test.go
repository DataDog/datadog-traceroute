// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package publicip

import (
	"context"
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
			wantErrMsg:       "client error: 400 Bad Request",
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
			name:             "status 404 returns permanent error",
			statusCode:       http.StatusNotFound,
			body:             "192.0.2.1",
			wantErr:          true,
			wantErrMsg:       "client error: 404 Not Found",
			wantPermanentErr: true,
		},
		{
			name:             "status 403 returns permanent error",
			statusCode:       http.StatusForbidden,
			body:             "192.0.2.1",
			wantErr:          true,
			wantErrMsg:       "client error: 403 Forbidden",
			wantPermanentErr: true,
		},
		{
			name:       "status 399 returns success",
			statusCode: 399,
			body:       "192.0.2.1",
			wantIP:     "192.0.2.1",
		},
		{
			name:             "status 499 returns permanent error",
			statusCode:       499,
			body:             "192.0.2.1",
			wantErr:          true,
			wantErrMsg:       "client error: 499",
			wantPermanentErr: true,
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
		name           string
		url            string
		contextTimeout time.Duration
		statusCode     int
		body           string
		serverDelay    time.Duration
		clientTimeout  time.Duration
		wantIP         string
		expectedErr    string
	}{
		{
			name:       "valid IPv4",
			statusCode: http.StatusOK,
			body:       "192.0.2.1",
			wantIP:     "192.0.2.1",
		},
		{
			name:        "valid IPv4 with whitespace",
			statusCode:  http.StatusOK,
			body:        "  192.0.2.1\n",
			wantIP:      "192.0.2.1",
			expectedErr: "",
		},
		{
			name:        "valid IPv6",
			statusCode:  http.StatusOK,
			body:        "2001:db8::1",
			wantIP:      "2001:db8::1",
			expectedErr: "",
		},
		{
			name:        "bad request 400",
			statusCode:  http.StatusBadRequest,
			body:        "192.0.2.1",
			expectedErr: "backoff retry error: client error: 400 Bad Request",
		},
		{
			name:        "invalid url",
			url:         string([]byte{1}),
			expectedErr: "failed to create new request: parse \"\\x01\": net/url: invalid control character in URL",
		},
		{
			name:           "context exceeded",
			url:            "*",
			contextTimeout: 1 * time.Millisecond,
			expectedErr:    "backoff retry error: context deadline exceeded",
		},
		{
			name:          "server responds within timeout",
			statusCode:    http.StatusOK,
			body:          "192.0.2.1",
			serverDelay:   100 * time.Millisecond,
			clientTimeout: 1 * time.Second,
			wantIP:        "192.0.2.1",
		},
		{
			name:          "server fails causing retries until ipCheckerCallTimeout expires",
			statusCode:    http.StatusInternalServerError,
			body:          "error",
			serverDelay:   50 * time.Millisecond,
			clientTimeout: 100 * time.Millisecond,
			expectedErr:   "backoff retry error: context deadline exceeded",
		},
		{
			name:           "parent context timeout shorter than ipCheckerCallTimeout",
			statusCode:     http.StatusInternalServerError, // Fail to trigger retries
			body:           "error",
			serverDelay:    10 * time.Millisecond,
			clientTimeout:  30 * time.Millisecond,  // Shorter than parent context timeout
			contextTimeout: 100 * time.Millisecond, // Expires before ipCheckerCallTimeout (2s)
			expectedErr:    "backoff retry error: context deadline exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.serverDelay > 0 {
					time.Sleep(tt.serverDelay)
				}
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client := server.Client()
			if tt.clientTimeout > 0 {
				client.Timeout = tt.clientTimeout
			}
			backoffPolicy := backoff.NewExponentialBackOff()
			backoffPolicy.InitialInterval = 1 * time.Millisecond
			backoffPolicy.MaxInterval = 5 * time.Millisecond
			if tt.serverDelay > 0 || tt.clientTimeout > 0 {
				// Use longer intervals for timeout tests to avoid flakiness
				backoffPolicy.InitialInterval = 10 * time.Millisecond
				backoffPolicy.MaxInterval = 50 * time.Millisecond
			}

			timeout := 1 * time.Second
			if tt.contextTimeout > 0 {
				timeout = tt.contextTimeout
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			url := server.URL
			if tt.url != "" {
				url = tt.url
			}

			gotIP, err := getPublicIPUsingIPChecker(ctx, client, backoffPolicy, url)

			if tt.expectedErr != "" {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.expectedErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, net.ParseIP(tt.wantIP), gotIP)
		})
	}
}

func TestGetPublicIP(t *testing.T) {
	// Save original ipCheckers and restore after tests
	originalIPCheckers := ipCheckers
	defer func() { ipCheckers = originalIPCheckers }()

	tests := []struct {
		name           string
		serverConfigs  []serverConfig // Configuration for each mock server
		wantIP         string
		wantErr        bool
		wantErrMsg     string
		contextTimeout time.Duration
	}{
		{
			name: "success on first checker",
			serverConfigs: []serverConfig{
				{statusCode: http.StatusOK, body: "192.0.2.1"},
				{statusCode: http.StatusOK, body: "192.0.2.2"},
				{statusCode: http.StatusOK, body: "192.0.2.3"},
			},
			wantIP: "192.0.2.1",
		},
		{
			name: "success on second checker (first fails)",
			serverConfigs: []serverConfig{
				{statusCode: http.StatusOK, body: "invalid"},
				{statusCode: http.StatusOK, body: "192.0.2.2"},
				{statusCode: http.StatusOK, body: "192.0.2.3"},
			},
			wantIP: "192.0.2.2",
		},
		{
			name: "success on last checker",
			serverConfigs: []serverConfig{
				{statusCode: http.StatusOK, body: "not-an-ip"},
				{statusCode: http.StatusOK, body: "also-not-an-ip"},
				{statusCode: http.StatusOK, body: "still-not-an-ip"},
				{statusCode: http.StatusOK, body: "nope"},
				{statusCode: http.StatusOK, body: "2001:db8::1"},
			},
			wantIP: "2001:db8::1",
		},
		{
			name: "all checkers fail with invalid IPs",
			serverConfigs: []serverConfig{
				{statusCode: http.StatusOK, body: "invalid1"},
				{statusCode: http.StatusOK, body: "invalid2"},
				{statusCode: http.StatusOK, body: "invalid3"},
			},
			wantErr:    true,
			wantErrMsg: "no IP found",
		},
		{
			name: "all checkers fail with errors",
			serverConfigs: []serverConfig{
				{statusCode: http.StatusBadRequest, body: "error"},
				{statusCode: http.StatusBadRequest, body: "error"},
				{statusCode: http.StatusBadRequest, body: "error"},
			},
			wantErr:    true,
			wantErrMsg: "no IP found",
		},
		{
			name: "mixed failures - invalid IP and HTTP errors",
			serverConfigs: []serverConfig{
				{statusCode: http.StatusOK, body: "not-valid"},
				{statusCode: http.StatusBadRequest, body: "192.0.2.1"},
				{statusCode: http.StatusOK, body: ""},
			},
			wantErr:    true,
			wantErrMsg: "no IP found",
		},
		{
			name: "success with IPv4",
			serverConfigs: []serverConfig{
				{statusCode: http.StatusOK, body: "  203.0.113.5\n"},
				{statusCode: http.StatusOK, body: "192.0.2.1"},
			},
			wantIP: "203.0.113.5",
		},
		{
			name: "success with IPv6",
			serverConfigs: []serverConfig{
				{statusCode: http.StatusOK, body: "2001:db8:85a3::8a2e:370:7334"},
			},
			wantIP: "2001:db8:85a3::8a2e:370:7334",
		},
		{
			name:          "empty server list",
			serverConfigs: []serverConfig{},
			wantErr:       true,
			wantErrMsg:    "no IP found",
		},
		{
			name: "first checker succeeds with whitespace handling",
			serverConfigs: []serverConfig{
				{statusCode: http.StatusOK, body: "\n\t  198.51.100.1  \t\n"},
			},
			wantIP: "198.51.100.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock servers
			servers := make([]*httptest.Server, len(tt.serverConfigs))
			checkerURLs := make([]string, len(tt.serverConfigs))

			for i, config := range tt.serverConfigs {
				cfg := config // Capture for closure
				servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if cfg.delay > 0 {
						time.Sleep(cfg.delay)
					}
					w.WriteHeader(cfg.statusCode)
					w.Write([]byte(cfg.body))
				}))
				checkerURLs[i] = servers[i].URL
			}

			// Clean up servers
			defer func() {
				for _, server := range servers {
					server.Close()
				}
			}()

			// Override the global ipCheckers with our test URLs
			ipCheckers = checkerURLs

			client := &http.Client{}
			backoffPolicy := backoff.NewExponentialBackOff()
			backoffPolicy.InitialInterval = 1 * time.Millisecond
			backoffPolicy.MaxInterval = 5 * time.Millisecond

			timeout := 1 * time.Second
			if tt.contextTimeout > 0 {
				timeout = tt.contextTimeout
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			gotIP, err := GetPublicIP(ctx, client, backoffPolicy)

			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErrMsg)
				assert.Nil(t, gotIP)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, net.ParseIP(tt.wantIP), gotIP)
		})
	}
}

// serverConfig holds configuration for a mock HTTP server
type serverConfig struct {
	statusCode int
	body       string
	delay      time.Duration
}
