//go:build !linux

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package common

import "net"

// LocalAddrForHost takes in a destination IP and port and returns the local
// address that should be used to connect to the destination. The returned connection
// should be closed by the caller when the local UDP port is no longer needed.
func LocalAddrForHost(destIP net.IP, destPort uint16) (*net.UDPAddr, net.Conn, error) {
	return dialLocalAddr(destIP, destPort)
}
