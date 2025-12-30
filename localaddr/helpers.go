// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package localaddr

import (
	"fmt"
	"net"
	"strconv"
)

func udpAddrFromConn(conn net.Conn) (*net.UDPAddr, error) {
	localAddr := conn.LocalAddr()

	localUDPAddr, ok := localAddr.(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("invalid address type for %s: want %T, got %T", localAddr, &net.UDPAddr{}, localAddr)
	}

	return localUDPAddr, nil
}

func normalizeLoopbackSource(destIP net.IP, addr *net.UDPAddr) {
	if destIP.IsLoopback() && addr != nil && !addr.IP.IsLoopback() {
		if destIP.To4() != nil {
			addr.IP = net.IPv4(127, 0, 0, 1)
		} else {
			addr.IP = net.IPv6loopback
		}
	}
}

func dialLocalAddr(destIP net.IP, destPort uint16) (*net.UDPAddr, net.Conn, error) {
	conn, err := net.Dial("udp", net.JoinHostPort(destIP.String(), strconv.Itoa(int(destPort))))
	if err != nil {
		return nil, nil, err
	}

	localUDPAddr, err := udpAddrFromConn(conn)
	if err != nil {
		return nil, nil, err
	}

	normalizeLoopbackSource(destIP, localUDPAddr)

	return localUDPAddr, conn, nil
}
