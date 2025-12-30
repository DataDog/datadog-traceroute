// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package localaddr_test

import (
	"net"
	"testing"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/localaddr"
	"github.com/stretchr/testify/require"
)

func TestLocalAddrForHost(t *testing.T) {
	t.Run("non-loopback destination", func(t *testing.T) {
		addr, conn, err := localaddr.LocalAddrForHost(net.ParseIP("8.8.8.8"), 53)
		require.NoError(t, err)
		require.NotNil(t, conn)
		defer conn.Close()
		require.NotNil(t, addr)
		require.NotNil(t, addr.IP)
		require.NotZero(t, addr.Port)
	})

	t.Run("IPv4 loopback destination returns loopback source", func(t *testing.T) {
		addr, conn, err := localaddr.LocalAddrForHost(net.ParseIP("127.0.0.1"), common.DefaultPort)
		require.NoError(t, err)
		require.NotNil(t, conn)
		defer conn.Close()
		require.NotNil(t, addr)
		require.True(t, addr.IP.IsLoopback(), "source IP %s should be loopback when destination is loopback", addr.IP)
	})

	t.Run("IPv6 loopback destination returns loopback source", func(t *testing.T) {
		addr, conn, err := localaddr.LocalAddrForHost(net.ParseIP("::1"), common.DefaultPort)
		require.NoError(t, err)
		require.NotNil(t, conn)
		defer conn.Close()
		require.NotNil(t, addr)
		require.True(t, addr.IP.IsLoopback(), "source IP %s should be loopback when destination is loopback", addr.IP)
	})
}
