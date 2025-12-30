// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package common contains common functionality for both TCP and UDP
// traceroute implementations
package common

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/net/ipv4"

	"github.com/DataDog/datadog-traceroute/log"
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

// LocalAddrForHost takes in a destination IP and port and returns the local
// address that should be used to connect to the destination. The returned connection
// should be closed by the caller when the local UDP port is no longer needed
func LocalAddrForHost(destIP net.IP, destPort uint16) (*net.UDPAddr, net.Conn, error) {
	// this is a quick way to get the local address for connecting to the host
	// using UDP as the network type to avoid actually creating a connection to
	// the host, just get the OS to give us a local IP and local ephemeral port
	conn, err := net.Dial("udp", net.JoinHostPort(destIP.String(), strconv.Itoa(int(destPort))))
	if err != nil {
		// Check if this is the netlink overflow error (occurs with WireGuard interfaces that have large interface indices)
		if isNetlinkOverflowError(err) {
			log.Debugf("Route lookup failed with netlink overflow error for %s, using interface enumeration fallback", destIP)
			return localAddrForHostFallback(destIP, destPort)
		}
		return nil, nil, err
	}
	localAddr := conn.LocalAddr()

	localUDPAddr, ok := localAddr.(*net.UDPAddr)
	if !ok {
		return nil, nil, fmt.Errorf("invalid address type for %s: want %T, got %T", localAddr, localUDPAddr, localAddr)
	}

	// On macOS, net.Dial() to a loopback destination may return a non-loopback local address.
	// Force the source to be a loopback address so packets can be properly routed.
	if destIP.IsLoopback() && !localUDPAddr.IP.IsLoopback() {
		if destIP.To4() != nil {
			localUDPAddr.IP = net.IPv4(127, 0, 0, 1)
		} else {
			localUDPAddr.IP = net.IPv6loopback
		}
	}

	return localUDPAddr, conn, nil
}

// isNetlinkOverflowError checks if the error is caused by netlink interface index overflow.
// This can happen with WireGuard interfaces that have very large interface indices.
func isNetlinkOverflowError(err error) bool {
	if err == nil {
		return false
	}
	// Check for "numerical result out of range" error string
	if strings.Contains(err.Error(), "numerical result out of range") {
		return true
	}
	// Check for syscall.ERANGE error
	return errors.Is(err, syscall.ERANGE)
}

// localAddrForHostFallback is a fallback method to determine the local address for a destination
// when the standard net.Dial approach fails. It enumerates network interfaces and selects an
// appropriate source IP address, preferring interfaces in the same subnet as the destination.
func localAddrForHostFallback(destIP net.IP, destPort uint16) (*net.UDPAddr, net.Conn, error) {
	// 1. Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to enumerate interfaces: %w", err)
	}

	// 2. Find suitable interface with an IP address
	var selectedIP net.IP
	var selectedIPNet *net.IPNet

	for _, iface := range interfaces {
		// Skip down or loopback interfaces (unless destination is loopback)
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if !destIP.IsLoopback() && iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		// Find an IP address on this interface
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP
			// Match IP version (v4 or v6)
			if (destIP.To4() != nil) != (ip.To4() != nil) {
				continue
			}

			// Prefer addresses in the same subnet as destination
			if ipNet.Contains(destIP) {
				selectedIP = ip
				selectedIPNet = ipNet
				break
			}

			// Otherwise, just pick the first valid IP as fallback
			if selectedIP == nil {
				selectedIP = ip
				selectedIPNet = ipNet
			}
		}

		// If we found an IP in the same subnet as destination, use it immediately
		if selectedIP != nil && selectedIPNet != nil && selectedIPNet.Contains(destIP) {
			break
		}
	}

	if selectedIP == nil {
		return nil, nil, fmt.Errorf("no suitable network interface found for destination %s", destIP)
	}

	log.Debugf("Selected source IP %s for destination %s", selectedIP, destIP)

	// 3. Create UDP connection with the selected local IP
	localAddr := &net.UDPAddr{IP: selectedIP, Port: 0}
	remoteAddr := &net.UDPAddr{IP: destIP, Port: int(destPort)}
	conn, err := net.DialUDP("udp", localAddr, remoteAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial with selected source IP %s: %w", selectedIP, err)
	}

	// Get the actual bound address (with ephemeral port)
	boundAddr := conn.LocalAddr().(*net.UDPAddr)

	// Apply loopback handling (same as in LocalAddrForHost)
	if destIP.IsLoopback() && !boundAddr.IP.IsLoopback() {
		if destIP.To4() != nil {
			boundAddr.IP = net.IPv4(127, 0, 0, 1)
		} else {
			boundAddr.IP = net.IPv6loopback
		}
	}

	return boundAddr, conn, nil
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
