// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package common

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

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
		listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		require.NoError(t, err)
		defer listener.Close()

		destination := listener.LocalAddr().(*net.UDPAddr)
		addr, conn, err := LocalAddrForHost(destination.IP, uint16(destination.Port))
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

	t.Run("IPv6 loopback destination returns loopback source", func(t *testing.T) {
		// When the destination is ::1, the source must also be a loopback address.
		addr, conn, err := LocalAddrForHost(net.ParseIP("::1"), DefaultPort)
		require.NoError(t, err)
		require.NotNil(t, conn)
		defer conn.Close()
		require.NotNil(t, addr)
		require.True(t, addr.IP.IsLoopback(), "source IP %s should be loopback when destination is loopback", addr.IP)
	})
}
