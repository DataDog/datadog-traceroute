// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package common contains common functionality for both TCP and UDP
// traceroute implementations
package common

import (
	"net"
	"net/netip"

	"golang.org/x/net/ipv4"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	DefaultNetworkPathTimeout    = 3000
	DefaultPort                  = 33434
	DefaultTracerouteQueries     = 3
	DefaultNumE2eProbes          = 50
	DefaultMinTTL                = 1
	DefaultMaxTTL                = 30
	DefaultDelay                 = 50 //msec
	DefaultProtocol              = "udp"
	DefaultTcpMethod             = "syn"
	DefaultWantV6                = false
	DefaultReverseDns            = false
	DefaultCollectSourcePublicIP = false
	DefaultUseWindowsDriver      = false
	DefaultSkipPrivateHops       = false
)

type (
	// CanceledError is sent when a listener
	// is canceled
	CanceledError string

	// MismatchError is an error type that indicates a MatcherFunc
	// failed due to one or more fields from the packet not matching
	// the expected information
	MismatchError string

	// MatcherFunc defines functions for matching a packet from the wire to
	// a traceroute based on the source/destination addresses and an identifier
	MatcherFunc func(*ipv4.Header, []byte, net.IP, uint16, net.IP, uint16, uint32, uint16) (net.IP, error)
)

// Error implements the error interface for
// CanceledError
func (c CanceledError) Error() string {
	return string(c)
}

// Error implements the error interface for
// MismatchError
func (m MismatchError) Error() string {
	return string(m)
}

// UnmappedAddrFromSlice is the same as netip.AddrFromSlice but it also gets rid of mapped ipv6 addresses.
func UnmappedAddrFromSlice(slice []byte) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(slice)
	return addr.Unmap(), ok
}

// IPFamily returns the IP family of an address (v4 or v6) as a gopacket layer
func IPFamily(addr netip.Addr) gopacket.LayerType {
	if addr.Is4() {
		return layers.LayerTypeIPv4
	}
	return layers.LayerTypeIPv6
}
