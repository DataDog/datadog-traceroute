// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package server

import (
	"net/url"
	"testing"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/traceroute"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				assert.Equal(t, "google.com", p.Hostname)
				assert.Equal(t, common.DefaultProtocol, p.Protocol)
				assert.Equal(t, common.DefaultPort, p.Port)
			},
		},
		{
			name:        "with protocol and port",
			queryString: "target=example.com&protocol=tcp&port=443",
			wantErr:     false,
			checkFunc: func(t *testing.T, p traceroute.TracerouteParams) {
				assert.Equal(t, "example.com", p.Hostname)
				assert.Equal(t, "tcp", p.Protocol)
				assert.Equal(t, 443, p.Port)
			},
		},
		{
			name:        "with boolean flags",
			queryString: "target=8.8.8.8&reverse-dns=true&ipv6=true&verbose=true",
			wantErr:     false,
			checkFunc: func(t *testing.T, p traceroute.TracerouteParams) {
				assert.True(t, p.ReverseDns, "expected ReverseDns to be true")
				assert.True(t, p.WantV6, "expected WantV6 to be true")
			},
		},
		{
			name:        "with numeric parameters",
			queryString: "target=test.com&max-ttl=20&traceroute-queries=5&timeout=5000",
			wantErr:     false,
			checkFunc: func(t *testing.T, p traceroute.TracerouteParams) {
				assert.Equal(t, 20, p.MaxTTL)
				assert.Equal(t, 5, p.TracerouteQueries)
				assert.Equal(t, 5000*time.Millisecond, p.Timeout)
			},
		},
		{
			name:        "with tcp method",
			queryString: "target=test.com&tcp-method=sack",
			wantErr:     false,
			checkFunc: func(t *testing.T, p traceroute.TracerouteParams) {
				assert.Equal(t, traceroute.TCPConfigSACK, p.TCPMethod)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse("/traceroute?" + tt.queryString)
			require.NoError(t, err, "failed to parse URL")

			params, err := parseTracerouteParams(u)

			if tt.wantErr {
				assert.Error(t, err, "expected error but got none")
				return
			}

			require.NoError(t, err)

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
		assert.Equal(t, "value1", getStringParam(query, "key1", "default"))
		assert.Equal(t, "default", getStringParam(query, "missing", "default"))
	})

	t.Run("getIntParam", func(t *testing.T) {
		query := map[string][]string{
			"num": {"42"},
			"bad": {"not-a-number"},
		}
		assert.Equal(t, 42, getIntParam(query, "num", 10))
		assert.Equal(t, 10, getIntParam(query, "missing", 10))
		assert.Equal(t, 10, getIntParam(query, "bad", 10), "should return default for invalid number")
	})

	t.Run("getBoolParam", func(t *testing.T) {
		query := map[string][]string{
			"true":  {"true"},
			"false": {"false"},
			"bad":   {"not-a-bool"},
		}
		assert.True(t, getBoolParam(query, "true", false))
		assert.False(t, getBoolParam(query, "false", true))
		assert.True(t, getBoolParam(query, "missing", true), "should return default for missing param")
		assert.True(t, getBoolParam(query, "bad", true), "should return default for invalid bool")
	})
}
