// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DataDog/datadog-traceroute/traceroute"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServer(t *testing.T) {
	srv := NewServer()
	require.NotNil(t, srv, "NewServer() returned nil")
	require.NotNil(t, srv.tr, "NewServer() did not initialize Traceroute instance")
}

func TestTracerouteHandlerMethodNotAllowed(t *testing.T) {
	srv := NewServer()
	req := httptest.NewRequest(http.MethodPost, "/traceroute?target=google.com", nil)
	w := httptest.NewRecorder()

	srv.TracerouteHandler(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestTracerouteHandlerMissingTarget(t *testing.T) {
	srv := NewServer()
	req := httptest.NewRequest(http.MethodGet, "/traceroute", nil)
	w := httptest.NewRecorder()

	srv.TracerouteHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var errResp traceroute.ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, traceroute.ErrCodeInvalidRequest, errResp.Code)
	assert.NotEmpty(t, errResp.Message)
}

func TestTracerouteHandlerDNSFailure(t *testing.T) {
	srv := NewServer()
	req := httptest.NewRequest(http.MethodGet, "/traceroute?target=nonexistent.invalid.host.example", nil)
	w := httptest.NewRecorder()

	srv.TracerouteHandler(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var errResp traceroute.ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, traceroute.ErrCodeDNS, errResp.Code)
	assert.NotEmpty(t, errResp.Message)
}

func TestTracerouteHandlerInvalidProtocol(t *testing.T) {
	srv := NewServer()
	req := httptest.NewRequest(http.MethodGet, "/traceroute?target=127.0.0.1&protocol=ftp", nil)
	w := httptest.NewRecorder()

	srv.TracerouteHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var errResp traceroute.ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, traceroute.ErrCodeInvalidRequest, errResp.Code)
}

func TestHealthHandler(t *testing.T) {
	srv := NewServer()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	srv.HealthHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response HealthResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "healthy", response.Status)
	assert.NotEmpty(t, response.Timestamp)
	assert.NotEmpty(t, response.Uptime)
}

func TestHealthHandlerHead(t *testing.T) {
	srv := NewServer()
	req := httptest.NewRequest(http.MethodHead, "/health", nil)
	w := httptest.NewRecorder()

	srv.HealthHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Empty(t, w.Body.String())
}

func TestHealthHandlerMethodNotAllowed(t *testing.T) {
	srv := NewServer()
	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	w := httptest.NewRecorder()

	srv.HealthHandler(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestTracerouteHandlerAuthentication(t *testing.T) {
	srv := NewServerWithOptions(Options{AuthToken: "test-token-placeholder"})
	tests := []struct {
		name          string
		authorization string
		wantStatus    int
	}{
		{name: "no header", authorization: "", wantStatus: http.StatusUnauthorized},
		{name: "wrong token", authorization: "Bearer other-token", wantStatus: http.StatusUnauthorized},
		{name: "token prefix only", authorization: "Bearer test-token", wantStatus: http.StatusUnauthorized},
		{name: "wrong scheme", authorization: "Basic test-token-placeholder", wantStatus: http.StatusUnauthorized},
		// A missing target fails validation, which shows the request got past authentication without sending packets.
		{name: "valid token", authorization: "Bearer test-token-placeholder", wantStatus: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/traceroute", nil)
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}
			w := httptest.NewRecorder()

			srv.TracerouteHandler(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
			if tt.wantStatus == http.StatusUnauthorized {
				assert.Equal(t, "Bearer", w.Header().Get("WWW-Authenticate"))
				var errResp traceroute.ErrorResponse
				require.NoError(t, json.NewDecoder(w.Body).Decode(&errResp))
				assert.Equal(t, traceroute.ErrCodeDenied, errResp.Code)
			}
		})
	}
}

func TestHealthHandlerDoesNotRequireToken(t *testing.T) {
	srv := NewServerWithOptions(Options{AuthToken: "test-token-placeholder"})
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	srv.HealthHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTracerouteHandlerBlockedTarget(t *testing.T) {
	blocked, err := ParseBlockedPrefixes([]string{"169.254.0.0/16", "fd00:ec2::254/128"})
	require.NoError(t, err)
	srv := NewServerWithOptions(Options{BlockedPrefixes: blocked})
	for _, query := range []string{
		"target=169.254.169.254&protocol=icmp",
		"target=169.254.169.254&protocol=tcp&port=80",
		"target=169.254.169.254&protocol=udp",
		"target=%3A%3Affff%3A169.254.169.254&protocol=icmp",
		"target=%5Bfd00%3Aec2%3A%3A254%5D&protocol=icmp&ipv6=true",
	} {
		t.Run(query, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/traceroute?"+query, nil)
			w := httptest.NewRecorder()

			srv.TracerouteHandler(w, req)

			assert.Equal(t, http.StatusForbidden, w.Code)
			var errResp traceroute.ErrorResponse
			require.NoError(t, json.NewDecoder(w.Body).Decode(&errResp))
			assert.Equal(t, traceroute.ErrCodeDenied, errResp.Code)
			assert.Contains(t, errResp.Message, "blocked range")
		})
	}
}
