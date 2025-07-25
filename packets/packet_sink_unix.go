// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build linux || darwin

package packets

import (
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

func getSockAddr(addr netip.Addr) (unix.Sockaddr, error) {
	switch {
	case addr.Is4():
		var sa4 unix.SockaddrInet4
		b := addr.As4()
		copy(sa4.Addr[:], b[:])
		return &sa4, nil
	case addr.Is6():
		var sa6 unix.SockaddrInet6
		b := addr.As16()
		copy(sa6.Addr[:], b[:])
		return &sa6, nil
	default:
		return nil, fmt.Errorf("invalid IP address")
	}
}
