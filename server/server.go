// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/DataDog/datadog-traceroute/log"
	"github.com/DataDog/datadog-traceroute/result"
	"github.com/DataDog/datadog-traceroute/traceroute"
)

// Server is the HTTP server for the traceroute API
type Server struct {
	tr        tracerouteRunner
	startTime time.Time
}

type tracerouteRunner interface {
	RunTraceroute(context.Context, traceroute.TracerouteParams) (*result.Results, error)
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Uptime    string `json:"uptime"`
}

// NewServer creates a new HTTP server with an initialized Traceroute instance
func NewServer() *Server {
	return &Server{
		tr:        traceroute.NewTraceroute(),
		startTime: time.Now(),
	}
}

// TracerouteHandler handles GET /traceroute requests
func (s *Server) TracerouteHandler(w http.ResponseWriter, r *http.Request) {
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
		} else if classified.Code == traceroute.ErrCodeTimeout {
			status = http.StatusGatewayTimeout
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
	mux := http.NewServeMux()
	mux.HandleFunc("/traceroute", s.TracerouteHandler)
	mux.HandleFunc("/health", s.HealthHandler)
	log.Debugf("Starting HTTP server on %s", addr)
	// ReadHeaderTimeout/IdleTimeout guard against slow-header and idle-connection
	// resource exhaustion without bounding the handler itself: a /traceroute request
	// can legitimately run as long as its own total_timeout_ms allows.
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return httpServer.ListenAndServe()
}
