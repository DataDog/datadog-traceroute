// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build windows

package packets

import (
	"fmt"
	"net/netip"

	"github.com/DataDog/datadog-agent/pkg/network/driver"
	"golang.org/x/sys/windows"
)

func createFilterAddress(addr netip.Addr) driver.FilterAddress {
	if addr.Is4() {
		return driver.FilterAddress{
			Af:         windows.AF_INET,
			V4_address: addr.As4(),
			Mask:       0xffffffff,
		}
	} else if addr.Is6() {
		return driver.FilterAddress{
			Af:         windows.AF_INET6,
			V6_address: addr.As16(),
			Mask:       0xffffffffffffffff,
		}
	}
	return driver.FilterAddress{}
}

// getAddressFamily determines the appropriate address family from an address
func getAddressFamily(addr netip.Addr) uint64 {
	if addr.Is6() {
		return uint64(windows.AF_INET6)
	}
	return uint64(windows.AF_INET)
}

// createBaseFilterDefinition creates a base filter definition with common fields
func createBaseFilterDefinition(af uint64) driver.FilterDefinition {
	return driver.FilterDefinition{
		FilterVersion:  driver.Signature,
		Size:           driver.FilterDefinitionSize,
		FilterLayer:    driver.LayerTransport,
		Af:             af,
		InterfaceIndex: uint64(0),
		Direction:      driver.DirectionInbound,
	}
}

// createTCPFilters creates filter definitions for TCP packet filtering
func createTCPFilters(spec PacketFilterSpec) []driver.FilterDefinition {
	af := getAddressFamily(spec.FilterConfig.Dst.Addr())

	// Create capture filter
	captureFilter := createBaseFilterDefinition(af)
	captureFilter.Protocol = windows.IPPROTO_TCP
	captureFilter.LocalAddress = createFilterAddress(spec.FilterConfig.Dst.Addr())
	captureFilter.RemoteAddress = createFilterAddress(spec.FilterConfig.Src.Addr())
	captureFilter.LocalPort = uint64(spec.FilterConfig.Dst.Port())
	captureFilter.RemotePort = uint64(spec.FilterConfig.Src.Port())

	// Create discard filter (same as capture but with Discard flag)
	discardFilter := captureFilter
	discardFilter.Discard = uint64(1)

	return []driver.FilterDefinition{captureFilter, discardFilter}
}

// createSYNACKFilters creates filter definitions for SYNACK packet filtering
func createSYNACKFilters(spec PacketFilterSpec) []driver.FilterDefinition {
	af := getAddressFamily(spec.FilterConfig.Src.Addr())

	// Create capture filter for SYNACK packets
	captureFilter := createBaseFilterDefinition(af)
	captureFilter.Protocol = windows.IPPROTO_TCP
	captureFilter.RemoteAddress = createFilterAddress(spec.FilterConfig.Src.Addr())
	captureFilter.RemotePort = uint64(spec.FilterConfig.Src.Port())

	// Create discard filter
	discardFilter := captureFilter
	discardFilter.Discard = uint64(1)

	return []driver.FilterDefinition{captureFilter, discardFilter}
}

// createNoneFilters creates filter definitions for capturing all packets (no specific filter)
// this should not be used
func createNoneFilters() []driver.FilterDefinition {
	var filters []driver.FilterDefinition

	// IPv4 filters
	ipv4Capture := createBaseFilterDefinition(windows.AF_INET)
	ipv4Discard := createBaseFilterDefinition(windows.AF_INET)
	ipv4Discard.Discard = uint64(1)

	// IPv6 filters
	ipv6Capture := createBaseFilterDefinition(windows.AF_INET6)
	ipv6Discard := createBaseFilterDefinition(windows.AF_INET6)
	ipv6Discard.Discard = uint64(1)

	filters = append(filters, ipv4Capture, ipv4Discard, ipv6Capture, ipv6Discard)
	return filters
}

// getWindowsFilter creates appropriate filter definitions based on the filter specification
func getWindowsFilter(spec PacketFilterSpec) ([]driver.FilterDefinition, error) {
	switch spec.FilterType {
	case FilterTypeICMP:
		// ICMP filters are already created by the driver setup
		return []driver.FilterDefinition{}, nil

	case FilterTypeTCP:
		return createTCPFilters(spec), nil

	case FilterTypeUDP:
		// UDP only uses the pre-installed ICMP filter
		return []driver.FilterDefinition{}, nil

	case FilterTypeSYNACK:
		return createSYNACKFilters(spec), nil

	case FilterTypeNone:
		return createNoneFilters(), nil

	default:
		return nil, fmt.Errorf("invalid filter type: %d", spec.FilterType)
	}
}
