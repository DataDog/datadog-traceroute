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
