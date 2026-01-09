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
	"golang.org/x/sys/windows"
)

func TestCreatePacketFilters(t *testing.T) {
	driver := &SourceDriver{}

	// Test TCP filter creation
	filters, err := driver.createPacketFilters(PacketFilterSpec{
		FilterType: FilterTypeTCP,
		FilterConfig: FilterConfig{
			Src: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 53),
			Dst: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 53),
		},
	})
	require.NoError(t, err)
	require.Len(t, filters, 4) // ICMP + TCP filter v4 + discard

	require.Equal(t, filters[0].Af, uint64(windows.AF_INET))
	// ipv6 icmp filter
	require.Equal(t, filters[1].Af, uint64(windows.AF_INET6))
	require.Equal(t, filters[2].Af, uint64(windows.AF_INET))
	// discard filter
	require.Equal(t, filters[3].Af, uint64(windows.AF_INET))

	// Test SYNACK filter creation
	driver3 := &SourceDriver{}
	filters, err = driver3.createPacketFilters(PacketFilterSpec{
		FilterType: FilterTypeSYNACK,
		FilterConfig: FilterConfig{
			Src: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 53),
		},
	})
	require.NoError(t, err)
	require.Len(t, filters, 4)

	require.Equal(t, filters[0].Af, uint64(windows.AF_INET))
	// ipv6 icmp filter
	require.Equal(t, filters[1].Af, uint64(windows.AF_INET6))
	require.Equal(t, filters[2].Af, uint64(windows.AF_INET))
	// discard filter
	require.Equal(t, filters[3].Af, uint64(windows.AF_INET))

	// Test UDP filter creation
	driver4 := &SourceDriver{}
	filters, err = driver4.createPacketFilters(PacketFilterSpec{
		FilterType: FilterTypeUDP,
	})
	require.NoError(t, err)
	require.Len(t, filters, 2) // only icmp filters (ipv4 and ipv6)

	// create ipv6 filter for tcp traffic
	driver5 := &SourceDriver{}
	filters, err = driver5.createPacketFilters(PacketFilterSpec{
		FilterType: FilterTypeTCP,
		FilterConfig: FilterConfig{
			Src: netip.AddrPortFrom(netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), 53),
			Dst: netip.AddrPortFrom(netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), 53),
		},
	})
	require.NoError(t, err)
	require.Len(t, filters, 4) // ICMP + TCP filter v4 + discard
	// initial ping filter (ipv4)
	require.Equal(t, filters[0].Af, uint64(windows.AF_INET))
	require.Equal(t, filters[1].Af, uint64(windows.AF_INET6))
	require.Equal(t, filters[2].Af, uint64(windows.AF_INET6))
	// discard filter
	require.Equal(t, filters[3].Af, uint64(windows.AF_INET6))

	// create ipv6 filter for synack traffic
	driver6 := &SourceDriver{}
	filters, err = driver6.createPacketFilters(PacketFilterSpec{
		FilterType: FilterTypeSYNACK,
		FilterConfig: FilterConfig{
			Src: netip.AddrPortFrom(netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), 53),
			Dst: netip.AddrPortFrom(netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), 53),
		},
	})
	require.NoError(t, err)
	require.Len(t, filters, 4) // ICMP + SYNACK filter v6 + discard
	// initial ping filter (ipv4)
	require.Equal(t, filters[0].Af, uint64(windows.AF_INET))
	require.Equal(t, filters[1].Af, uint64(windows.AF_INET6))
	require.Equal(t, filters[2].Af, uint64(windows.AF_INET6))
	// discard filter
	require.Equal(t, filters[3].Af, uint64(windows.AF_INET6))
}
