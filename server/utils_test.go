// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package server

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/traceroute"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTracerouteParams(t *testing.T) {
	t.Run("missing target returns error", func(t *testing.T) {
		u, err := url.Parse("/traceroute?")
		require.NoError(t, err)

		_, err = parseTracerouteParams(u)
		assert.Error(t, err, "expected error when target is missing")
		assert.Contains(t, err.Error(), "missing required parameter: target")
	})

	t.Run("all default values", func(t *testing.T) {
		u, err := url.Parse("/traceroute?target=example.com")
		require.NoError(t, err)

		params, err := parseTracerouteParams(u)
		require.NoError(t, err)

		// Expected params with all default values
		expected := traceroute.TracerouteParams{
			Hostname:                  "example.com",
			Port:                      common.DefaultPort,
			Protocol:                  common.DefaultProtocol,
			MinTTL:                    common.DefaultMinTTL,
			MaxTTL:                    common.DefaultMaxTTL,
			Delay:                     common.DefaultDelay,
			Timeout:                   time.Duration(common.DefaultNetworkPathTimeout) * time.Millisecond,
			TotalTimeout:              time.Duration(common.DefaultTotalTimeoutMs) * time.Millisecond,
			TCPMethod:                 traceroute.TCPMethod(common.DefaultTcpMethod),
			WantV6:                    false,
			TCPSynParisTracerouteMode: false,
			ReverseDns:                false,
			CollectSourcePublicIP:     false,
			TracerouteQueries:         common.DefaultTracerouteQueries,
			E2eQueries:                common.DefaultNumE2eProbes,
			UseWindowsDriver:          false,
			SkipPrivateHops:           false,
		}

		assert.Equal(t, expected, params, "all fields should match default values")
	})

	t.Run("all custom values", func(t *testing.T) {
		queryString := "target=custom.example.com" +
			"&protocol=tcp" +
			"&port=8080" +
			"&max-ttl=64" +
			"&timeout=10000" +
			"&total_timeout_ms=30000" +
			"&tcp-method=sack" +
			"&traceroute-queries=5" +
			"&e2e-queries=100" +
			"&ipv6=true" +
			"&reverse-dns=true" +
			"&source-public-ip=true" +
			"&windows-driver=true" +
			"&skip-private-hops=true"

		u, err := url.Parse("/traceroute?" + queryString)
		require.NoError(t, err)

		params, err := parseTracerouteParams(u)
		require.NoError(t, err)

		// Expected params with all custom values
		expected := traceroute.TracerouteParams{
			Hostname:                  "custom.example.com",
			Port:                      8080,
			Protocol:                  "tcp",
			MinTTL:                    common.DefaultMinTTL, // Not customizable via query params
			MaxTTL:                    64,
			Delay:                     common.DefaultDelay, // Not customizable via query params
			Timeout:                   10000 * time.Millisecond,
			TotalTimeout:              30000 * time.Millisecond,
			TCPMethod:                 traceroute.TCPConfigSACK,
			WantV6:                    true,
			TCPSynParisTracerouteMode: false, // Not customizable via query params
			ReverseDns:                true,
			CollectSourcePublicIP:     true,
			TracerouteQueries:         5,
			E2eQueries:                100,
			UseWindowsDriver:          true,
			SkipPrivateHops:           true,
		}

		assert.Equal(t, expected, params, "all fields should match custom values")
	})

	t.Run("per-hop timeout and total timeout are independently settable", func(t *testing.T) {
		u, err := url.Parse("/traceroute?target=example.com&timeout=500&total_timeout_ms=15000")
		require.NoError(t, err)

		params, err := parseTracerouteParams(u)
		require.NoError(t, err)

		assert.Equal(t, 500*time.Millisecond, params.Timeout)
		assert.Equal(t, 15000*time.Millisecond, params.TotalTimeout)
	})

	t.Run("total timeout defaults to disabled when omitted", func(t *testing.T) {
		u, err := url.Parse("/traceroute?target=example.com&timeout=500")
		require.NoError(t, err)

		params, err := parseTracerouteParams(u)
		require.NoError(t, err)

		assert.Equal(t, 500*time.Millisecond, params.Timeout)
		assert.Equal(t, time.Duration(0), params.TotalTimeout)
	})

	t.Run("total_timeout_ms alone preserves the default per-probe timeout", func(t *testing.T) {
		u, err := url.Parse("/traceroute?target=example.com&total_timeout_ms=10000")
		require.NoError(t, err)

		params, err := parseTracerouteParams(u)
		require.NoError(t, err)

		assert.Equal(t, time.Duration(common.DefaultNetworkPathTimeout)*time.Millisecond, params.Timeout)
		assert.Equal(t, 10000*time.Millisecond, params.TotalTimeout)
	})

	t.Run("explicit timeout alongside total_timeout_ms is preserved", func(t *testing.T) {
		u, err := url.Parse("/traceroute?target=example.com&timeout=500&total_timeout_ms=10000")
		require.NoError(t, err)

		params, err := parseTracerouteParams(u)
		require.NoError(t, err)

		assert.Equal(t, 500*time.Millisecond, params.Timeout)
		assert.Equal(t, 10000*time.Millisecond, params.TotalTimeout)
	})

	t.Run("explicit zero timeout disables the per-probe deadline", func(t *testing.T) {
		u, err := url.Parse("/traceroute?target=example.com&timeout=0&total_timeout_ms=10000")
		require.NoError(t, err)

		params, err := parseTracerouteParams(u)
		require.NoError(t, err)

		assert.Equal(t, time.Duration(0), params.Timeout)
		assert.Equal(t, 10000*time.Millisecond, params.TotalTimeout)
	})

	t.Run("maximum representable max-ttl is accepted", func(t *testing.T) {
		u, err := url.Parse(fmt.Sprintf("/traceroute?target=example.com&max-ttl=%d", common.MaxAllowedTTL))
		require.NoError(t, err)

		params, err := parseTracerouteParams(u)
		require.NoError(t, err)
		assert.Equal(t, common.MaxAllowedTTL, params.MaxTTL)
	})

	for _, maxTTL := range []string{"0", "-1", "256", "not-a-number", ""} {
		t.Run("invalid max-ttl "+maxTTL+" is rejected", func(t *testing.T) {
			u, err := url.Parse("/traceroute?target=example.com&max-ttl=" + maxTTL)
			require.NoError(t, err)

			_, err = parseTracerouteParams(u)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "max-ttl")
		})
	}

	t.Run("negative total_timeout_ms is rejected", func(t *testing.T) {
		u, err := url.Parse("/traceroute?target=example.com&total_timeout_ms=-1")
		require.NoError(t, err)

		_, err = parseTracerouteParams(u)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "total_timeout_ms")
	})

	t.Run("negative timeout is rejected", func(t *testing.T) {
		u, err := url.Parse("/traceroute?target=example.com&timeout=-1")
		require.NoError(t, err)

		_, err = parseTracerouteParams(u)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "timeout")
	})

	t.Run("malformed total_timeout_ms is rejected instead of silently defaulting", func(t *testing.T) {
		u, err := url.Parse("/traceroute?target=example.com&total_timeout_ms=not-a-number")
		require.NoError(t, err)

		_, err = parseTracerouteParams(u)
		require.Error(t, err)
	})

	t.Run("explicitly empty total_timeout_ms is rejected rather than treated as absent", func(t *testing.T) {
		u, err := url.Parse("/traceroute?target=example.com&total_timeout_ms=")
		require.NoError(t, err)

		_, err = parseTracerouteParams(u)
		require.Error(t, err)
	})

	t.Run("large total_timeout_ms values are still accepted for backward compatibility", func(t *testing.T) {
		// only overflow of time.Duration should be rejected, not a "reasonable" business cap
		u, err := url.Parse("/traceroute?target=example.com&total_timeout_ms=99999999999")
		require.NoError(t, err)

		params, err := parseTracerouteParams(u)
		require.NoError(t, err)
		assert.Equal(t, 99999999999*time.Millisecond, params.TotalTimeout)
	})

	t.Run("total_timeout_ms exceeding time.Duration's range is rejected", func(t *testing.T) {
		u, err := url.Parse(fmt.Sprintf("/traceroute?target=example.com&total_timeout_ms=%d", common.MaxTimeoutMs+1))
		require.NoError(t, err)

		_, err = parseTracerouteParams(u)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "total_timeout_ms")
	})
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
