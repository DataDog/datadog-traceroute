// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package common

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestResolveProbeTimeout(t *testing.T) {
	tests := []struct {
		name              string
		configuredTimeout time.Duration
		totalTimeout      time.Duration
		maxTTL            int
		sendDelay         time.Duration
		configured        bool
		expected          time.Duration
	}{
		{
			name:              "derives timeout from total timeout and max TTL",
			configuredTimeout: 3 * time.Second,
			totalTimeout:      10 * time.Second,
			maxTTL:            30,
			expected:          300 * time.Millisecond,
		},
		{
			name:              "uses custom max TTL when deriving timeout",
			configuredTimeout: 3 * time.Second,
			totalTimeout:      10 * time.Second,
			maxTTL:            20,
			expected:          450 * time.Millisecond,
		},
		{
			name:              "preserves explicit timeout",
			configuredTimeout: 500 * time.Millisecond,
			totalTimeout:      10 * time.Second,
			maxTTL:            30,
			configured:        true,
			expected:          500 * time.Millisecond,
		},
		{
			name:         "explicit zero timeout is treated as unset",
			totalTimeout: 10 * time.Second,
			maxTTL:       30,
			configured:   true,
			expected:     300 * time.Millisecond,
		},
		{
			name:              "uses legacy default without total timeout",
			configuredTimeout: 3 * time.Second,
			maxTTL:            30,
			expected:          3 * time.Second,
		},
		{
			name:     "uses default timeout when neither timeout is set",
			maxTTL:   30,
			expected: 3 * time.Second,
		},
		{
			name:         "derived timeout is floored at MinProbeTimeout",
			totalTimeout: time.Nanosecond,
			maxTTL:       30,
			expected:     MinProbeTimeout,
		},
		{
			name:         "send delay is subtracted from the derived per-hop budget",
			totalTimeout: 10 * time.Second,
			maxTTL:       30,
			sendDelay:    100 * time.Millisecond,
			expected:     200 * time.Millisecond,
		},
		{
			name:         "send delay larger than the per-hop budget is floored at MinProbeTimeout",
			totalTimeout: 10 * time.Second,
			maxTTL:       30,
			sendDelay:    time.Second,
			expected:     MinProbeTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, ResolveProbeTimeout(
				tt.configuredTimeout,
				tt.totalTimeout,
				tt.maxTTL,
				tt.sendDelay,
				tt.configured,
			))
		})
	}
}

func TestValidateQueryCount(t *testing.T) {
	require.NoError(t, ValidateQueryCount("queries", 0, 10))
	require.NoError(t, ValidateQueryCount("queries", 10, 10))
	require.Error(t, ValidateQueryCount("queries", -1, 10))
	require.Error(t, ValidateQueryCount("queries", 11, 10))
}

func TestUnmappedAddrFromSliceZero(t *testing.T) {
	// zero value
	addr, ok := UnmappedAddrFromSlice(nil)
	require.Equal(t, netip.Addr{}, addr)
	require.False(t, ok)
}

func TestUnmappedAddrFromSliceIPv4(t *testing.T) {
	addr, ok := UnmappedAddrFromSlice(net.ParseIP("192.168.1.1"))
	require.Equal(t, netip.MustParseAddr("192.168.1.1"), addr)
	require.True(t, ok)
}

func TestUnmappedAddrFromSliceIPv6(t *testing.T) {
	addr, ok := UnmappedAddrFromSlice(net.ParseIP("::1"))
	require.Equal(t, netip.MustParseAddr("::1"), addr)
	require.True(t, ok)
}

func TestUnmappedAddrFromSliceMappedIPv4(t *testing.T) {
	addr, ok := UnmappedAddrFromSlice(net.ParseIP("::ffff:54.146.50.212"))
	require.Equal(t, netip.MustParseAddr("54.146.50.212"), addr)
	require.True(t, ok)
}

func TestLocalAddrForHost(t *testing.T) {
	t.Run("non-loopback destination", func(t *testing.T) {
		// For a non-loopback destination the returned address should be a valid local address.
		addr, conn, err := LocalAddrForHost(net.ParseIP("8.8.8.8"), 53)
		require.NoError(t, err)
		require.NotNil(t, conn)
		defer conn.Close()
		require.NotNil(t, addr)
		require.NotNil(t, addr.IP)
		require.NotZero(t, addr.Port)
	})

	t.Run("IPv4 loopback destination returns loopback source", func(t *testing.T) {
		// When the destination is 127.0.0.1, the source must also be a loopback address.
		addr, conn, err := LocalAddrForHost(net.ParseIP("127.0.0.1"), DefaultPort)
		require.NoError(t, err)
		require.NotNil(t, conn)
		defer conn.Close()
		require.NotNil(t, addr)
		require.True(t, addr.IP.IsLoopback(), "source IP %s should be loopback when destination is loopback", addr.IP)
	})
}
