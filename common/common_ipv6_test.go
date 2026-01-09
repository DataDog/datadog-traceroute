//go:build test && ipv6
// +build test,ipv6

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package common

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// Runs under the ipv6 build tag because some environments lack IPv6 loopback support.
func TestLocalAddrForHostIPv6Loopback(t *testing.T) {
	// When the destination is ::1, the source must also be a loopback address.
	addr, conn, err := LocalAddrForHost(net.ParseIP("::1"), DefaultPort)
	require.NoError(t, err)
	require.NotNil(t, conn)
	defer conn.Close()
	require.NotNil(t, addr)
	require.True(t, addr.IP.IsLoopback(), "source IP %s should be loopback when destination is loopback", addr.IP)
}
