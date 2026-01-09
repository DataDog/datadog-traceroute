// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build !linux

package common

import (
	"net"
)

// RouteInfo contains route information for a destination
type RouteInfo struct {
	// SrcIP is the source IP address to use for reaching the destination
	SrcIP net.IP
	// InterfaceIndex is the index of the network interface for the route
	InterfaceIndex int
	// Gateway is the gateway IP address, if any
	Gateway net.IP
}

// GetRouteInfo returns route information for reaching the given destination IP.
// On non-Linux platforms, this uses UDP dial to determine the source IP.
func GetRouteInfo(destIP net.IP) (*RouteInfo, error) {
	addr, conn, err := LocalAddrForHost(destIP, DefaultPort)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return &RouteInfo{
		SrcIP:          addr.IP,
		InterfaceIndex: 0,
		Gateway:        nil,
	}, nil
}
