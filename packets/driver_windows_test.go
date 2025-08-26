// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build windows

package packets

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreatePacketFilters(t *testing.T) {
	driver := &SourceDriver{}

	// Test TCP filter creation
	filters, err := driver.createPacketFilters(PacketFilterSpec{
		FilterType: FilterTypeTCP,
		TCPFilterConfig: TCPFilterConfig{
			Src: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 53),
			Dst: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 53),
		},
	})
	require.NoError(t, err)
	require.Len(t, filters, 2) // ICMP + TCP filter

	// Add same filter again, should be a no-op
	filters, err = driver.createPacketFilters(PacketFilterSpec{
		FilterType: FilterTypeTCP,
		TCPFilterConfig: TCPFilterConfig{
			Src: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 53),
			Dst: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 53),
		},
	})
	require.NoError(t, err)
	require.Len(t, filters, 0) // No new filters created

	// Test UDP filter creation
	driver2 := &SourceDriver{}
	filters, err = driver2.createPacketFilters(PacketFilterSpec{
		FilterType: FilterTypeUDP,
	})
	require.NoError(t, err)
	require.Len(t, filters, 2) // ICMP + UDP filter

	// Test SYNACK filter creation
	driver3 := &SourceDriver{}
	filters, err = driver3.createPacketFilters(PacketFilterSpec{
		FilterType: FilterTypeSYNACK,
	})
	require.NoError(t, err)
	require.Len(t, filters, 2) // ICMP + SYNACK filter
}
