//go:build linux

package localaddr

import (
	"fmt"
	"math"
	"net"

	"github.com/vishvananda/netlink"
)

type RouteInfo struct {
	IfIndex uint32
	PrefSrc net.IP
}

type routeGetFunc func(dst net.IP) ([]netlink.Route, error)

var routeGet routeGetFunc = netlink.RouteGet

func lookupOutboundRoute(destIP net.IP) (RouteInfo, error) {
	routes, err := routeGet(destIP)
	if err != nil {
		return RouteInfo{}, fmt.Errorf("netlink route lookup failed: %w", err)
	}
	for _, r := range routes {
		ifIndex, err := toUint32IfIndex(r.LinkIndex)
		if err != nil {
			return RouteInfo{}, err
		}
		prefSrc := routeSourceIP(r)
		if prefSrc == nil {
			continue
		}
		return RouteInfo{IfIndex: ifIndex, PrefSrc: prefSrc}, nil
	}
	return RouteInfo{}, fmt.Errorf("no valid route found for %s", destIP)
}

func routeSourceIP(r netlink.Route) net.IP {
	if len(r.Src) > 0 {
		return r.Src
	}
	return nil
}

func toUint32IfIndex(idx int) (uint32, error) {
	switch {
	case idx < 0:
		return uint32(uint64(idx) & math.MaxUint32), nil
	case idx > math.MaxUint32:
		return 0, fmt.Errorf("link index %d overflows uint32", idx)
	default:
		return uint32(idx), nil
	}
}
