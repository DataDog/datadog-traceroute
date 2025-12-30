//go:build linux

package localaddr

import (
	"errors"
	"math"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

func TestLookupOutboundRouteHandlesLargeIfIndex(t *testing.T) {
	originalRouteGet := routeGet
	t.Cleanup(func() { routeGet = originalRouteGet })

	const largeIndex = uint32(1<<31) + 5
	prefSrc := net.ParseIP("192.0.2.10")
	routeGet = func(dst net.IP) ([]netlink.Route, error) {
		return []netlink.Route{{
			LinkIndex: int(largeIndex),
			Src:       prefSrc,
		}}, nil
	}

	info, err := lookupOutboundRoute(net.ParseIP("203.0.113.1"))
	require.NoError(t, err)
	require.Equal(t, largeIndex, info.IfIndex)
	require.Equal(t, prefSrc, info.PrefSrc)
}

func TestLookupOutboundRouteRejectsOverflowingIndex(t *testing.T) {
	originalRouteGet := routeGet
	t.Cleanup(func() { routeGet = originalRouteGet })

	routeGet = func(dst net.IP) ([]netlink.Route, error) {
		return []netlink.Route{{
			LinkIndex: int(math.MaxUint32) + 1,
			Src:       net.ParseIP("192.0.2.10"),
		}}, nil
	}

	_, err := lookupOutboundRoute(net.ParseIP("203.0.113.1"))
	require.Error(t, err)
}

func TestLocalAddrForHostFallsBackWhenRouteFails(t *testing.T) {
	originalRouteGet := routeGet
	t.Cleanup(func() { routeGet = originalRouteGet })

	routeGet = func(dst net.IP) ([]netlink.Route, error) {
		return nil, errors.New("boom")
	}

	addr, conn, err := LocalAddrForHost(net.ParseIP("127.0.0.1"), 33434)
	require.NoError(t, err)
	require.NotNil(t, addr)
	require.NotNil(t, conn)
	conn.Close()
}

func TestLocalAddrForHostUsesRouteSource(t *testing.T) {
	originalRouteGet := routeGet
	t.Cleanup(func() { routeGet = originalRouteGet })

	src := net.IPv4(127, 0, 0, 2)
	routeGet = func(dst net.IP) ([]netlink.Route, error) {
		return []netlink.Route{{
			LinkIndex: 2,
			Src:       src,
		}}, nil
	}

	addr, conn, err := LocalAddrForHost(net.ParseIP("127.0.0.1"), 33434)
	require.NoError(t, err)
	require.Equal(t, src.String(), addr.IP.String())
	conn.Close()
}
