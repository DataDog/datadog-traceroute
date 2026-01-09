// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build linux

package common

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
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
// It uses the netlink library to query the kernel routing table.
// On certain interfaces (like WireGuard), the netlink query may fail with ERANGE
// due to integer overflow issues in parsing netlink messages. In such cases,
// this function falls back to using UDP dial to determine the source IP.
func GetRouteInfo(destIP net.IP) (*RouteInfo, error) {
	routes, err := netlink.RouteGet(destIP)
	if err != nil {
		// Check for ERANGE error which can occur on interfaces with unusual
		// configurations (like WireGuard). This happens when netlink message
		// attributes contain values that overflow the expected integer types.
		if isERANGE(err) {
			return getRouteInfoFallback(destIP)
		}
		// Also fall back for any other netlink error to ensure graceful degradation
		return getRouteInfoFallback(destIP)
	}

	if len(routes) == 0 {
		return getRouteInfoFallback(destIP)
	}

	route := routes[0]

	// If route.Src is nil, netlink didn't provide the source IP
	// This can happen on certain interface types
	if route.Src == nil {
		return getRouteInfoFallback(destIP)
	}

	return &RouteInfo{
		SrcIP:          route.Src,
		InterfaceIndex: route.LinkIndex,
		Gateway:        route.Gw,
	}, nil
}

// isERANGE checks if the error is due to a numerical result out of range,
// which can occur when parsing netlink messages with values that overflow.
func isERANGE(err error) bool {
	if err == nil {
		return false
	}
	// Use errors.Is for proper error chain checking
	if errors.Is(err, syscall.ERANGE) {
		return true
	}
	// Also check the error message for the string "numerical result out of range"
	// as some errors may not be properly wrapped
	if strings.Contains(err.Error(), "numerical result out of range") {
		return true
	}
	return false
}

// getRouteInfoFallback uses UDP dial as a fallback method to determine
// the source IP for reaching a destination when netlink fails.
func getRouteInfoFallback(destIP net.IP) (*RouteInfo, error) {
	// Use the existing LocalAddrForHost function which uses UDP dial
	addr, conn, err := LocalAddrForHost(destIP, DefaultPort)
	if err != nil {
		return nil, fmt.Errorf("fallback route lookup failed: %w", err)
	}
	defer conn.Close()

	return &RouteInfo{
		SrcIP:          addr.IP,
		InterfaceIndex: 0, // Cannot determine interface index via UDP dial
		Gateway:        nil,
	}, nil
}
