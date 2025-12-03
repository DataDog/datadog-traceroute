// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/traceroute"
)

func TestParseTracerouteParams(t *testing.T) {
	tests := []struct {
		name        string
		queryString string
		wantErr     bool
		checkFunc   func(*testing.T, traceroute.TracerouteParams)
	}{
		{
			name:        "missing target",
			queryString: "",
			wantErr:     true,
		},
		{
			name:        "basic target only",
			queryString: "target=google.com",
			wantErr:     false,
			checkFunc: func(t *testing.T, p traceroute.TracerouteParams) {
				if p.Hostname != "google.com" {
					t.Errorf("expected hostname 'google.com', got '%s'", p.Hostname)
				}
				if p.Protocol != common.DefaultProtocol {
					t.Errorf("expected default protocol '%s', got '%s'", common.DefaultProtocol, p.Protocol)
				}
				if p.Port != common.DefaultPort {
					t.Errorf("expected default port %d, got %d", common.DefaultPort, p.Port)
				}
			},
		},
		{
			name:        "with protocol and port",
			queryString: "target=example.com&protocol=tcp&port=443",
			wantErr:     false,
			checkFunc: func(t *testing.T, p traceroute.TracerouteParams) {
				if p.Hostname != "example.com" {
					t.Errorf("expected hostname 'example.com', got '%s'", p.Hostname)
				}
				if p.Protocol != "tcp" {
					t.Errorf("expected protocol 'tcp', got '%s'", p.Protocol)
				}
				if p.Port != 443 {
					t.Errorf("expected port 443, got %d", p.Port)
				}
			},
		},
		{
			name:        "with boolean flags",
			queryString: "target=8.8.8.8&reverse-dns=true&ipv6=true&verbose=true",
			wantErr:     false,
			checkFunc: func(t *testing.T, p traceroute.TracerouteParams) {
				if !p.ReverseDns {
					t.Error("expected ReverseDns to be true")
				}
				if !p.WantV6 {
					t.Error("expected WantV6 to be true")
				}
			},
		},
		{
			name:        "with numeric parameters",
			queryString: "target=test.com&max-ttl=20&traceroute-queries=5&timeout=5000",
			wantErr:     false,
			checkFunc: func(t *testing.T, p traceroute.TracerouteParams) {
				if p.MaxTTL != 20 {
					t.Errorf("expected max-ttl 20, got %d", p.MaxTTL)
				}
				if p.TracerouteQueries != 5 {
					t.Errorf("expected traceroute-queries 5, got %d", p.TracerouteQueries)
				}
				if p.Timeout != 5000*time.Millisecond {
					t.Errorf("expected timeout 5000ms, got %v", p.Timeout)
				}
			},
		},
		{
			name:        "with tcp method",
			queryString: "target=test.com&tcp-method=sack",
			wantErr:     false,
			checkFunc: func(t *testing.T, p traceroute.TracerouteParams) {
				if p.TCPMethod != "sack" {
					t.Errorf("expected tcp-method 'sack', got '%s'", p.TCPMethod)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/traceroute?"+tt.queryString, nil)
			params, err := parseTracerouteParams(req.URL)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if tt.checkFunc != nil {
				tt.checkFunc(t, params)
			}
		})
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("getStringParam", func(t *testing.T) {
		query := map[string][]string{
			"key1": {"value1"},
		}
		if got := getStringParam(query, "key1", "default"); got != "value1" {
			t.Errorf("expected 'value1', got '%s'", got)
		}
		if got := getStringParam(query, "missing", "default"); got != "default" {
			t.Errorf("expected 'default', got '%s'", got)
		}
	})

	t.Run("getIntParam", func(t *testing.T) {
		query := map[string][]string{
			"num": {"42"},
			"bad": {"not-a-number"},
		}
		if got := getIntParam(query, "num", 10); got != 42 {
			t.Errorf("expected 42, got %d", got)
		}
		if got := getIntParam(query, "missing", 10); got != 10 {
			t.Errorf("expected 10, got %d", got)
		}
		if got := getIntParam(query, "bad", 10); got != 10 {
			t.Errorf("expected 10 (default), got %d", got)
		}
	})

	t.Run("getBoolParam", func(t *testing.T) {
		query := map[string][]string{
			"true":  {"true"},
			"false": {"false"},
			"bad":   {"not-a-bool"},
		}
		if got := getBoolParam(query, "true", false); !got {
			t.Error("expected true")
		}
		if got := getBoolParam(query, "false", true); got {
			t.Error("expected false")
		}
		if got := getBoolParam(query, "missing", true); !got {
			t.Error("expected true (default)")
		}
		if got := getBoolParam(query, "bad", true); !got {
			t.Error("expected true (default)")
		}
	})
}
