// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/DataDog/datadog-traceroute/log"
	"github.com/DataDog/datadog-traceroute/traceroute"
)

// Server is the HTTP server for the traceroute API
type Server struct {
	tr *traceroute.Traceroute
}

// NewServer creates a new HTTP server with an initialized Traceroute instance
func NewServer() *Server {
	return &Server{
		tr: traceroute.NewTraceroute(),
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
		http.Error(w, fmt.Sprintf("Invalid parameters: %v", err), http.StatusBadRequest)
		return
	}

	// Run traceroute
	results, err := s.tr.RunTraceroute(r.Context(), params)
	if err != nil {
		http.Error(w, fmt.Sprintf("Traceroute failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(results); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}
}

// Start starts the HTTP server on the specified address
func (s *Server) Start(addr string) error {
	http.HandleFunc("/traceroute", s.TracerouteHandler)
	log.Debugf("Starting HTTP server on %s", addr)
	return http.ListenAndServe(addr, nil)
}
