// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package server

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/DataDog/datadog-traceroute/log"
	"github.com/DataDog/datadog-traceroute/traceroute"
)

// Server is the HTTP server for the traceroute API
type Server struct {
	tr        *traceroute.Traceroute
	startTime time.Time
	authToken []byte
}

// Options configures access control for a Server.
type Options struct {
	// AuthToken, when not empty, must be sent as "Authorization: Bearer <AuthToken>" on /traceroute.
	AuthToken string
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Uptime    string `json:"uptime"`
}

// NewServer creates a new HTTP server with an initialized Traceroute instance
func NewServer() *Server {
	return NewServerWithOptions(Options{})
}

// NewServerWithOptions creates a new HTTP server that applies opts to every /traceroute request
func NewServerWithOptions(opts Options) *Server {
	return &Server{
		tr:        traceroute.NewTraceroute(),
		startTime: time.Now(),
		authToken: []byte(opts.AuthToken),
	}
}

func (s *Server) isAuthorized(r *http.Request) bool {
	if len(s.authToken) == 0 {
		return true
	}
	scheme, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
	return found && strings.EqualFold(scheme, "Bearer") &&
		subtle.ConstantTimeCompare([]byte(strings.TrimLeft(token, " ")), s.authToken) == 1
}

// TracerouteHandler handles GET /traceroute requests
func (s *Server) TracerouteHandler(w http.ResponseWriter, r *http.Request) {
	if !s.isAuthorized(r) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeErrorResponse(w, traceroute.ErrorResponse{
			Code:    traceroute.ErrCodeDenied,
			Message: "missing or invalid bearer token",
		}, http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse query parameters
	params, err := parseTracerouteParams(r.URL)
	if err != nil {
		writeErrorResponse(w, traceroute.ErrorResponse{
			Code:    traceroute.ErrCodeInvalidRequest,
			Message: err.Error(),
		}, http.StatusBadRequest)
		return
	}

	// Run traceroute
	results, err := s.tr.RunTraceroute(r.Context(), params)
	if err != nil {
		classified := traceroute.ClassifyError(err)
		status := http.StatusInternalServerError
		if classified.Code == traceroute.ErrCodeInvalidRequest {
			status = http.StatusBadRequest
		}
		writeErrorResponse(w, traceroute.ErrorResponse{
			Code:    classified.Code,
			Message: classified.Message,
		}, status)
		return
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(results); err != nil {
		writeErrorResponse(w, traceroute.ErrorResponse{
			Code:    traceroute.ErrCodeFailedEncoding,
			Message: "Failed to encode response",
		}, http.StatusInternalServerError)
		return
	}
}

// HealthHandler handles GET /health requests for sidecar health checks
func (s *Server) HealthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uptime := time.Since(s.startTime)
	response := HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Uptime:    uptime.String(),
	}

	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		writeErrorResponse(w, traceroute.ErrorResponse{
			Code:    traceroute.ErrCodeFailedEncoding,
			Message: "Failed to encode health response",
		}, http.StatusInternalServerError)
		return
	}
}

// writeErrorResponse writes a structured JSON error to the response.
func writeErrorResponse(w http.ResponseWriter, resp traceroute.ErrorResponse, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Errorf("failed to encode error response: %v", err)
	}
}

// Start starts the HTTP server on the specified address
func (s *Server) Start(addr string) error {
	log.Debugf("Starting HTTP server on %s", addr)
	return s.httpServer(addr).ListenAndServe()
}

// httpServer builds the HTTP server, with its own mux and a header timeout.
func (s *Server) httpServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/traceroute", s.TracerouteHandler)
	mux.HandleFunc("/health", s.HealthHandler)
	// No write timeout: a traceroute can run for minutes.
	return &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
}
