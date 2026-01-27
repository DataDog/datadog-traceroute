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
