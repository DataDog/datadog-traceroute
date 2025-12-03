// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
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
	params, err := s.parseTracerouteParams(r)
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

// parseTracerouteParams extracts and validates query parameters from the HTTP request
func (s *Server) parseTracerouteParams(r *http.Request) (traceroute.TracerouteParams, error) {
	query := r.URL.Query()

	// Required parameter: hostname (target)
	hostname := query.Get("target")
	if hostname == "" {
		return traceroute.TracerouteParams{}, fmt.Errorf("missing required parameter: target")
	}

	// Parse optional parameters with defaults
	protocol := getStringParam(query, "protocol", common.DefaultProtocol)
	port := getIntParam(query, "port", common.DefaultPort)
	tracerouteQueries := getIntParam(query, "traceroute-queries", common.DefaultTracerouteQueries)
	maxTTL := getIntParam(query, "max-ttl", common.DefaultMaxTTL)
	timeoutMs := getIntParam(query, "timeout", int(common.DefaultNetworkPathTimeout))
	tcpMethod := getStringParam(query, "tcp-method", common.DefaultTcpMethod)
	e2eQueries := getIntParam(query, "e2e-queries", common.DefaultNumE2eProbes)

	// Parse boolean flags
	wantV6 := getBoolParam(query, "ipv6", false)
	reverseDns := getBoolParam(query, "reverse-dns", false)
	collectSourcePublicIP := getBoolParam(query, "source-public-ip", false)
	useWindowsDriver := getBoolParam(query, "windows-driver", false)
	skipPrivateHops := getBoolParam(query, "skip-private-hops", false)

	// Set verbose logging
	log.EnabledLogging(true)

	// Construct traceroute parameters
	params := traceroute.TracerouteParams{
		Hostname:              hostname,
		Port:                  port,
		Protocol:              protocol,
		MinTTL:                common.DefaultMinTTL,
		MaxTTL:                maxTTL,
		Delay:                 common.DefaultDelay,
		Timeout:               time.Duration(timeoutMs) * time.Millisecond,
		TCPMethod:             traceroute.TCPMethod(tcpMethod),
		WantV6:                wantV6,
		ReverseDns:            reverseDns,
		CollectSourcePublicIP: collectSourcePublicIP,
		TracerouteQueries:     tracerouteQueries,
		E2eQueries:            e2eQueries,
		UseWindowsDriver:      useWindowsDriver,
		SkipPrivateHops:       skipPrivateHops,
	}

	return params, nil
}

// Start starts the HTTP server on the specified address
func (s *Server) Start(addr string) error {
	http.HandleFunc("/traceroute", s.TracerouteHandler)
	log.Debugf("Starting HTTP server on %s", addr)
	return http.ListenAndServe(addr, nil)
}
