//go:build linux

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package common

import (
	"fmt"
	"net"
	"strconv"

	"github.com/vishvananda/netlink"

	"github.com/DataDog/datadog-traceroute/log"
)

var (
	routeGet    = netlink.RouteGet
	linkByIndex = netlink.LinkByIndex
	addrList    = netlink.AddrList
)

// LocalAddrForHost takes in a destination IP and port and returns the local
// address that should be used to connect to the destination. The returned connection
// should be closed by the caller when the local UDP port is no longer needed.
//
// On Linux, we prefer asking the kernel for the route to the destination via
// netlink so we can get the exact source IP/interface the kernel would use. This
// helps in environments such as WireGuard where the routing table lives in a
// high-numbered table and the source address may not be derived correctly from a
// naive dial. RouteGet can return EOVERFLOW on hosts with many routes (including
// WireGuard policy routing), so we log and fall back to the standard dial-based
// implementation instead of declaring the path down.
func LocalAddrForHost(destIP net.IP, destPort uint16) (*net.UDPAddr, net.Conn, error) {
	addr, conn, err := localAddrViaNetlink(destIP, destPort)
	if err == nil {
		return addr, conn, nil
	}

	log.Debugf("netlink route lookup failed, falling back to dial: %v", err)
	addr, conn, dialErr := localAddrViaDial(destIP, destPort)
	if dialErr == nil {
		return addr, conn, nil
	}

	log.Debugf("dial fallback failed, using best-effort listener: %v", dialErr)
	anyAddr, anyConn, anyErr := localAddrAny(destIP)
	if anyErr == nil {
		return anyAddr, anyConn, nil
	}

	return nil, nil, fmt.Errorf("failed to determine local addr: netlink err=%v, dial err=%w, listen err=%v", err, dialErr, anyErr)
}

func localAddrViaNetlink(destIP net.IP, destPort uint16) (*net.UDPAddr, net.Conn, error) {
	routes, err := routeGet(destIP)
	if err != nil {
		return nil, nil, fmt.Errorf("netlink route lookup failed: %w", err)
	}
	if len(routes) == 0 {
		return nil, nil, fmt.Errorf("netlink returned no routes for %s", destIP)
	}

	route := routes[0]
	src := route.Src

	// If the kernel didn't provide a source, derive one from the interface addresses.
	if src == nil && route.LinkIndex != 0 {
		link, linkErr := linkByIndex(route.LinkIndex)
		if linkErr != nil {
			return nil, nil, fmt.Errorf("netlink failed to fetch link %d: %w", route.LinkIndex, linkErr)
		}
		// Prefer an address family that matches the destination.
		family := netlink.FAMILY_V4
		if destIP.To4() == nil {
			family = netlink.FAMILY_V6
		}
		addrs, addrErr := addrList(link, family)
		if addrErr != nil {
			return nil, nil, fmt.Errorf("netlink failed to list addrs for link %d: %w", route.LinkIndex, addrErr)
		}
		for _, a := range addrs {
			if a.IP == nil {
				continue
			}
			if (destIP.To4() != nil && a.IP.To4() != nil) || (destIP.To4() == nil && a.IP.To4() == nil) {
				src = a.IP
				break
			}
		}
	}

	if src == nil {
		return nil, nil, fmt.Errorf("could not determine source IP for route to %s", destIP)
	}

	// Use a connected UDP socket bound to the chosen source so we get an
	// ephemeral port directly from the kernel for this route/interface.
	remote := net.JoinHostPort(destIP.String(), strconv.Itoa(int(destPort)))
	conn, err := net.DialUDP("udp", &net.UDPAddr{IP: src}, &net.UDPAddr{IP: destIP, Port: int(destPort)})
	if err != nil {
		// If we cannot connect to the destination (e.g., no default route in
		// the test environment), still try to reserve an ephemeral port on the
		// chosen source interface.
		listenConn, listenErr := net.ListenUDP("udp", &net.UDPAddr{IP: src})
		if listenErr != nil {
			return nil, nil, fmt.Errorf("failed to dial UDP with source %s to %s: %w", src, remote, err)
		}
		conn = listenConn
	}

	localUDPAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		conn.Close()
		return nil, nil, fmt.Errorf("invalid address type for %s: want %T, got %T", conn.LocalAddr(), &net.UDPAddr{}, conn.LocalAddr())
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

// localAddrViaDial retains the previous dial-based behaviour as a fallback.
func localAddrViaDial(destIP net.IP, destPort uint16) (*net.UDPAddr, net.Conn, error) {
	conn, err := net.Dial("udp", net.JoinHostPort(destIP.String(), strconv.Itoa(int(destPort))))
	if err != nil {
		return nil, nil, err
	}
	localAddr := conn.LocalAddr()

	localUDPAddr, ok := localAddr.(*net.UDPAddr)
	if !ok {
		return nil, nil, fmt.Errorf("invalid address type for %s: want %T, got %T", localAddr, localUDPAddr, localAddr)
	}

	if destIP.IsLoopback() && !localUDPAddr.IP.IsLoopback() {
		if destIP.To4() != nil {
			localUDPAddr.IP = net.IPv4(127, 0, 0, 1)
		} else {
			localUDPAddr.IP = net.IPv6loopback
		}
	}

	return localUDPAddr, conn, nil
}

func localAddrAny(destIP net.IP) (*net.UDPAddr, net.Conn, error) {
	laddr := &net.UDPAddr{}
	if destIP.IsLoopback() {
		if destIP.To4() != nil {
			laddr.IP = net.IPv4(127, 0, 0, 1)
		} else {
			laddr.IP = net.IPv6loopback
		}
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, nil, err
	}

	localUDPAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		conn.Close()
		return nil, nil, fmt.Errorf("invalid address type for %s: want %T, got %T", conn.LocalAddr(), &net.UDPAddr{}, conn.LocalAddr())
	}

	return localUDPAddr, conn, nil
}
