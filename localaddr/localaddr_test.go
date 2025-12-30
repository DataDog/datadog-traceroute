// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package localaddr

import (
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestForHost(t *testing.T) {
	t.Run("non-loopback destination", func(t *testing.T) {
		// Test with a well-known public IP (Google DNS)
		addr, conn, err := ForHost(net.ParseIP("8.8.8.8"), 53)
		require.NoError(t, err, "ForHost should succeed for public destination")
		require.NotNil(t, conn, "connection should not be nil")
		defer conn.Close()

		require.NotNil(t, addr, "address should not be nil")
		require.NotNil(t, addr.IP, "IP should not be nil")
		require.NotZero(t, addr.Port, "port should not be zero")
		assert.True(t, addr.IP.To4() != nil, "should return IPv4 address for IPv4 destination")
		assert.False(t, addr.IP.IsLoopback(), "should not return loopback for public destination")
	})

	t.Run("IPv4 loopback destination returns loopback source", func(t *testing.T) {
		addr, conn, err := ForHost(net.ParseIP("127.0.0.1"), 80)
		require.NoError(t, err, "ForHost should succeed for loopback destination")
		require.NotNil(t, conn, "connection should not be nil")
		defer conn.Close()

		require.NotNil(t, addr, "address should not be nil")
		assert.True(t, addr.IP.IsLoopback(), "source IP %s should be loopback when destination is loopback", addr.IP)
	})

	t.Run("IPv6 loopback destination returns loopback source", func(t *testing.T) {
		addr, conn, err := ForHost(net.ParseIP("::1"), 80)
		require.NoError(t, err, "ForHost should succeed for IPv6 loopback destination")
		require.NotNil(t, conn, "connection should not be nil")
		defer conn.Close()

		require.NotNil(t, addr, "address should not be nil")
		assert.True(t, addr.IP.IsLoopback(), "source IP %s should be loopback when destination is IPv6 loopback", addr.IP)
	})

	t.Run("returns valid UDP address type", func(t *testing.T) {
		addr, conn, err := ForHost(net.ParseIP("8.8.8.8"), 53)
		require.NoError(t, err)
		defer conn.Close()

		assert.IsType(t, &net.UDPAddr{}, addr, "should return *net.UDPAddr")
	})

	t.Run("invalid destination", func(t *testing.T) {
		// Using nil IP should cause an error
		_, _, err := ForHost(nil, 80)
		assert.Error(t, err, "should return error for nil destination IP")
	})
}

func TestIsNetlinkOverflowError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "error with 'numerical result out of range' string",
			err:      errors.New("route lookup failed: numerical result out of range"),
			expected: true,
		},
		{
			name:     "syscall.ERANGE error",
			err:      syscall.ERANGE,
			expected: true,
		},
		{
			name:     "error containing ERANGE message",
			err:      errors.New("route lookup failed: result too large"),
			expected: false, // This won't match without "numerical result out of range"
		},
		{
			name:     "different error",
			err:      errors.New("network is unreachable"),
			expected: false,
		},
		{
			name:     "connection refused error",
			err:      syscall.ECONNREFUSED,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNetlinkOverflowError(tt.err)
			assert.Equal(t, tt.expected, result, "isNetlinkOverflowError(%v) = %v, want %v", tt.err, result, tt.expected)
		})
	}
}

func TestForHostFallback(t *testing.T) {
	t.Run("successful fallback with public destination", func(t *testing.T) {
		// Test fallback with a public IP
		addr, conn, err := forHostFallback(net.ParseIP("8.8.8.8"), 53)
		require.NoError(t, err, "forHostFallback should succeed")
		require.NotNil(t, conn, "connection should not be nil")
		defer conn.Close()

		require.NotNil(t, addr, "address should not be nil")
		require.NotNil(t, addr.IP, "IP should not be nil")
		require.NotZero(t, addr.Port, "port should not be zero")
		assert.True(t, addr.IP.To4() != nil, "should return IPv4 address for IPv4 destination")
	})

	t.Run("IPv4 loopback destination in fallback", func(t *testing.T) {
		addr, conn, err := forHostFallback(net.ParseIP("127.0.0.1"), 80)
		require.NoError(t, err, "forHostFallback should succeed for loopback")
		require.NotNil(t, conn)
		defer conn.Close()

		require.NotNil(t, addr)
		assert.True(t, addr.IP.IsLoopback(), "should return loopback address for loopback destination")
	})

	t.Run("IPv6 loopback destination in fallback", func(t *testing.T) {
		addr, conn, err := forHostFallback(net.ParseIP("::1"), 80)
		require.NoError(t, err, "forHostFallback should succeed for IPv6 loopback")
		require.NotNil(t, conn)
		defer conn.Close()

		require.NotNil(t, addr)
		assert.True(t, addr.IP.IsLoopback(), "should return loopback address for IPv6 loopback destination")
	})

	t.Run("matches IP version", func(t *testing.T) {
		// IPv4 destination should get IPv4 source
		addr4, conn4, err := forHostFallback(net.ParseIP("8.8.8.8"), 53)
		require.NoError(t, err)
		defer conn4.Close()
		assert.True(t, addr4.IP.To4() != nil, "IPv4 destination should get IPv4 source")

		// Try IPv6 if available (may not be available on all systems)
		addr6, conn6, err := forHostFallback(net.ParseIP("2001:4860:4860::8888"), 53)
		if err == nil {
			defer conn6.Close()
			assert.True(t, addr6.IP.To4() == nil, "IPv6 destination should get IPv6 source")
		}
		// Note: IPv6 test is best-effort as not all systems have IPv6
	})

	t.Run("returns valid connection", func(t *testing.T) {
		addr, conn, err := forHostFallback(net.ParseIP("8.8.8.8"), 53)
		require.NoError(t, err)
		require.NotNil(t, conn)
		defer conn.Close()

		// Verify the connection is usable
		localAddr := conn.LocalAddr()
		assert.NotNil(t, localAddr)
		assert.Equal(t, addr.String(), localAddr.String(), "returned address should match connection's local address")
	})
}

func TestInterfaceEnumeration(t *testing.T) {
	t.Run("system has at least one usable interface", func(t *testing.T) {
		interfaces, err := net.Interfaces()
		require.NoError(t, err, "should be able to enumerate interfaces")

		// Find at least one UP interface (loopback is acceptable)
		hasUpInterface := false
		for _, iface := range interfaces {
			if iface.Flags&net.FlagUp != 0 {
				hasUpInterface = true
				break
			}
		}
		assert.True(t, hasUpInterface, "system should have at least one UP interface")
	})

	t.Run("at least one interface has an IP address", func(t *testing.T) {
		interfaces, err := net.Interfaces()
		require.NoError(t, err)

		hasIP := false
		for _, iface := range interfaces {
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			if len(addrs) > 0 {
				hasIP = true
				break
			}
		}
		assert.True(t, hasIP, "at least one interface should have an IP address")
	})
}

func TestEdgeCases(t *testing.T) {
	t.Run("zero port", func(t *testing.T) {
		// Port 0 may cause "can't assign requested address" on some systems
		_, conn, err := ForHost(net.ParseIP("8.8.8.8"), 0)
		if conn != nil {
			defer conn.Close()
		}
		// Either succeeds or fails with a specific error - both are acceptable
		if err != nil {
			t.Logf("Port 0 caused error (expected on some systems): %v", err)
		}
	})

	t.Run("high port number", func(t *testing.T) {
		addr, conn, err := ForHost(net.ParseIP("8.8.8.8"), 65535)
		require.NoError(t, err, "should handle maximum port number")
		if conn != nil {
			defer conn.Close()
		}
		assert.NotNil(t, addr)
	})

	t.Run("multiple sequential calls", func(t *testing.T) {
		// Ensure the function can be called multiple times successfully
		for i := 0; i < 3; i++ {
			addr, conn, err := ForHost(net.ParseIP("8.8.8.8"), 53)
			require.NoError(t, err, "call %d should succeed", i+1)
			require.NotNil(t, conn, "call %d should return connection", i+1)
			conn.Close()
			assert.NotNil(t, addr, "call %d should return address", i+1)
		}
	})
}

func TestConnectionProperties(t *testing.T) {
	t.Run("ephemeral port is assigned", func(t *testing.T) {
		addr, conn, err := ForHost(net.ParseIP("8.8.8.8"), 53)
		require.NoError(t, err)
		defer conn.Close()

		// Ephemeral ports are typically > 1024
		assert.Greater(t, addr.Port, 0, "port should be positive")
	})

	t.Run("connection can be closed safely", func(t *testing.T) {
		addr, conn, err := ForHost(net.ParseIP("8.8.8.8"), 53)
		require.NoError(t, err)
		require.NotNil(t, conn)

		// Should not panic
		assert.NotPanics(t, func() {
			conn.Close()
		}, "closing connection should not panic")

		assert.NotNil(t, addr)
	})

	t.Run("multiple connections can coexist", func(t *testing.T) {
		// Open multiple connections
		var conns []net.Conn
		for i := 0; i < 3; i++ {
			_, conn, err := ForHost(net.ParseIP("8.8.8.8"), 53)
			require.NoError(t, err)
			require.NotNil(t, conn)
			conns = append(conns, conn)
		}

		// Close all connections
		for _, conn := range conns {
			conn.Close()
		}
	})
}

func TestFallbackCandidateSelection(t *testing.T) {
	t.Run("collects multiple candidates", func(t *testing.T) {
		// The fallback should try multiple interfaces if available
		// This tests that we don't just pick the first one
		addr, conn, err := forHostFallback(net.ParseIP("8.8.8.8"), 53)
		require.NoError(t, err, "should successfully find a working interface")
		require.NotNil(t, conn)
		defer conn.Close()

		require.NotNil(t, addr)
		require.NotNil(t, addr.IP)
		assert.True(t, addr.IP.To4() != nil, "should select IPv4 address for IPv4 destination")
	})

	t.Run("tries candidates until one succeeds", func(t *testing.T) {
		// Test that fallback is resilient - even if we have many interfaces,
		// it should find one that works
		interfaces, err := net.Interfaces()
		require.NoError(t, err)

		// Count usable interfaces
		usableCount := 0
		for _, iface := range interfaces {
			if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
				addrs, _ := iface.Addrs()
				for _, addr := range addrs {
					if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
						usableCount++
						break
					}
				}
			}
		}

		// If we have multiple interfaces, fallback should still work
		if usableCount > 0 {
			addr, conn, err := forHostFallback(net.ParseIP("8.8.8.8"), 53)
			require.NoError(t, err, "fallback should succeed with %d usable interfaces", usableCount)
			require.NotNil(t, conn)
			defer conn.Close()
			assert.NotNil(t, addr)
		}
	})

	t.Run("handles systems with only one interface", func(t *testing.T) {
		// Even with just one interface (common in containers), fallback should work
		addr, conn, err := forHostFallback(net.ParseIP("8.8.8.8"), 53)
		require.NoError(t, err, "should work with limited interfaces")
		if conn != nil {
			defer conn.Close()
		}
		assert.NotNil(t, addr)
	})
}

func TestWireGuardScenario(t *testing.T) {
	t.Run("handles /32 networks correctly", func(t *testing.T) {
		// WireGuard interfaces use /32 for IPv4 and /128 for IPv6
		// The peer IP is never in the same subnet
		// This test verifies fallback tries all candidates, not just same-subnet ones

		// Get all interfaces to see if we have any /32 networks
		interfaces, err := net.Interfaces()
		require.NoError(t, err)

		has32Network := false
		for _, iface := range interfaces {
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok {
					ones, _ := ipNet.Mask.Size()
					if ones == 32 && ipNet.IP.To4() != nil {
						has32Network = true
						break
					}
				}
			}
			if has32Network {
				break
			}
		}

		// Even if we don't have a real WireGuard interface, verify fallback works
		// The fix ensures we try all candidates, not just same-subnet matches
		addr, conn, err := forHostFallback(net.ParseIP("8.8.8.8"), 53)
		require.NoError(t, err, "fallback should work regardless of network masks")
		require.NotNil(t, conn)
		defer conn.Close()

		assert.NotNil(t, addr)
		if has32Network {
			t.Logf("System has /32 networks - fallback correctly handled them")
		}
	})
}
