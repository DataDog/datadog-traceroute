// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package common

import (
	"net"

	"github.com/DataDog/datadog-traceroute/common/localaddr"
)

// LocalAddrForHost delegates to the platform-specific localaddr package so the
// public API remains under the common package.
func LocalAddrForHost(destIP net.IP, destPort uint16) (*net.UDPAddr, net.Conn, error) {
	return localaddr.LocalAddrForHost(destIP, destPort)
}
