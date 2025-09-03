// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

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

func getWindowsFilter(spec PacketFilterSpec) ([]driver.FilterDefinition, error) {
	switch spec.FilterType {
	case FilterTypeICMP:
		// don't make icmp filter, it's already created
		return []driver.FilterDefinition{}, nil
	case FilterTypeTCP:
		// get Af from address
		af := uint64(windows.AF_INET)
		if spec.FilterConfig.Dst.Addr().Is6() {
			af = uint64(windows.AF_INET6)
		}
		return []driver.FilterDefinition{
			{
				FilterVersion:  driver.Signature,
				Size:           driver.FilterDefinitionSize,
				FilterLayer:    driver.LayerTransport,
				Af:             af,
				InterfaceIndex: uint64(0),
				Direction:      driver.DirectionInbound,
				Protocol:       windows.IPPROTO_TCP,
				LocalAddress:   createFilterAddress(spec.FilterConfig.Dst.Addr()),
				RemoteAddress:  createFilterAddress(spec.FilterConfig.Src.Addr()),
				LocalPort:      uint64(spec.FilterConfig.Dst.Port()),
				RemotePort:     uint64(spec.FilterConfig.Src.Port()),
			},
			// need to capture the discard packets
			{
				FilterVersion:  driver.Signature,
				Size:           driver.FilterDefinitionSize,
				FilterLayer:    driver.LayerTransport,
				Af:             af,
				InterfaceIndex: uint64(0),
				Direction:      driver.DirectionInbound,
				Protocol:       windows.IPPROTO_TCP,
				LocalAddress:   createFilterAddress(spec.FilterConfig.Dst.Addr()),
				RemoteAddress:  createFilterAddress(spec.FilterConfig.Src.Addr()),
				LocalPort:      uint64(spec.FilterConfig.Dst.Port()),
				RemotePort:     uint64(spec.FilterConfig.Src.Port()),
				Discard:        uint64(1),
			},
		}, nil
	case FilterTypeUDP:
		// udp only uses installed icmp filter
		return []driver.FilterDefinition{}, nil
	case FilterTypeSYNACK:
		// we have the remote filter address and port, so fill that in
		// get af
		af := uint64(windows.AF_INET)
		if spec.FilterConfig.Src.Addr().Is6() {
			af = uint64(windows.AF_INET6)
		}
		return []driver.FilterDefinition{
			{
				FilterVersion:  driver.Signature,
				Size:           driver.FilterDefinitionSize,
				FilterLayer:    driver.LayerTransport,
				Af:             af,
				InterfaceIndex: uint64(0),
				Direction:      driver.DirectionInbound,
				Protocol:       windows.IPPROTO_TCP,
				RemoteAddress:  createFilterAddress(spec.FilterConfig.Src.Addr()),
				RemotePort:     uint64(spec.FilterConfig.Src.Port()),
			},
			{
				FilterVersion:  driver.Signature,
				Size:           driver.FilterDefinitionSize,
				FilterLayer:    driver.LayerTransport,
				Af:             af,
				InterfaceIndex: uint64(0),
				Direction:      driver.DirectionInbound,
				Protocol:       windows.IPPROTO_TCP,
				RemoteAddress:  createFilterAddress(spec.FilterConfig.Src.Addr()),
				RemotePort:     uint64(spec.FilterConfig.Src.Port()),
				Discard:        uint64(1),
			},
		}, nil
	case FilterTypeNone:
		return []driver.FilterDefinition{
			{
				FilterVersion:  driver.Signature,
				Size:           driver.FilterDefinitionSize,
				FilterLayer:    driver.LayerTransport,
				Af:             windows.AF_INET,
				InterfaceIndex: uint64(0),
				Direction:      driver.DirectionInbound,
			},
			{
				FilterVersion:  driver.Signature,
				Size:           driver.FilterDefinitionSize,
				FilterLayer:    driver.LayerTransport,
				Af:             windows.AF_INET,
				InterfaceIndex: uint64(0),
				Direction:      driver.DirectionInbound,
				Discard:        uint64(1),
			},
			// create ipv6 filters
			{
				FilterVersion:  driver.Signature,
				Size:           driver.FilterDefinitionSize,
				FilterLayer:    driver.LayerTransport,
				Af:             windows.AF_INET6,
				InterfaceIndex: uint64(0),
				Direction:      driver.DirectionInbound,
			},
			{
				FilterVersion:  driver.Signature,
				Size:           driver.FilterDefinitionSize,
				FilterLayer:    driver.LayerTransport,
				Af:             windows.AF_INET6,
				InterfaceIndex: uint64(0),
				Direction:      driver.DirectionInbound,
				Discard:        uint64(1),
			},
		}, nil
	}

	return nil, fmt.Errorf("invalid filter type: %d", spec.FilterType)
}
