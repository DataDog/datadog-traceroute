// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package localaddr

import (
	"fmt"
	"net"
	"strconv"
)

// LocalAddrForHost takes in a destination IP and port and returns the local
// address that should be used to connect to the destination. The returned connection
// should be closed by the caller when the local UDP port is no longer needed
func LocalAddrForHost(destIP net.IP, destPort uint16) (*net.UDPAddr, net.Conn, error) {
	conn, err := dialWithRoute(destIP, destPort)
	if err != nil {
		conn, err = net.Dial("udp", net.JoinHostPort(destIP.String(), strconv.Itoa(int(destPort))))
		if err != nil {
			return nil, nil, err
		}
	}

	localUDPAddr, err := normalizeLocalAddr(destIP, conn.LocalAddr())
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	return localUDPAddr, conn, nil
}

func dialWithRoute(destIP net.IP, destPort uint16) (net.Conn, error) {
	routeInfo, err := lookupOutboundRoute(destIP)
	if err != nil {
		return nil, fmt.Errorf("route lookup failed: %w", err)
	}
	if routeInfo.PrefSrc == nil {
		return nil, fmt.Errorf("route lookup returned no preferred source IP")
	}

	localUDPAddr := &net.UDPAddr{IP: routeInfo.PrefSrc}
	conn, err := net.DialUDP("udp", localUDPAddr, &net.UDPAddr{IP: destIP, Port: int(destPort)})
	if err != nil {
		return nil, fmt.Errorf("dialing with route source failed: %w", err)
	}

	return conn, nil
}

func normalizeLocalAddr(destIP net.IP, localAddr net.Addr) (*net.UDPAddr, error) {
	localUDPAddr, ok := localAddr.(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("invalid address type for %s: want %T, got %T", localAddr, localUDPAddr, localAddr)
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

	return localUDPAddr, nil
}
