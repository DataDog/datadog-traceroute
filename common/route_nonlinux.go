//go:build !linux

package common

import (
	"fmt"
	"net"
)

type RouteInfo struct {
	IfIndex uint32
	PrefSrc net.IP
}

func lookupOutboundRoute(destIP net.IP) (RouteInfo, error) {
	return RouteInfo{}, fmt.Errorf("netlink route lookup unsupported on this platform")
}
