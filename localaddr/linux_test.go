//go:build linux

package localaddr

import (
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestLocalAddrViaNetlinkWithSrc(t *testing.T) {
	originalRouteGet := routeGet
	originalLinkByIndex := linkByIndex
	originalAddrList := addrList
	defer func() {
		routeGet = originalRouteGet
		linkByIndex = originalLinkByIndex
		addrList = originalAddrList
	}()

	routeGet = func(_ net.IP) ([]netlink.Route, error) {
		return []netlink.Route{{Src: net.IPv4(127, 0, 0, 1)}}, nil
	}
	linkByIndex = func(_ int) (netlink.Link, error) {
		return &netlink.Dummy{}, nil
	}
	addrList = func(_ netlink.Link, _ int) ([]netlink.Addr, error) {
		return nil, nil
	}

	addr, conn, err := LocalAddrForHost(net.IPv4(127, 0, 0, 1), 33434)
	if err != nil {
		t.Fatalf("LocalAddrForHost returned error: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	if !addr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("expected loopback IP from netlink, got %s", addr.IP)
	}
	if addr.Port == 0 {
		t.Fatalf("expected an ephemeral port to be assigned")
	}
}

func TestLocalAddrViaNetlinkDerivesSrcFromLink(t *testing.T) {
	originalRouteGet := routeGet
	originalLinkByIndex := linkByIndex
	originalAddrList := addrList
	defer func() {
		routeGet = originalRouteGet
		linkByIndex = originalLinkByIndex
		addrList = originalAddrList
	}()

	routeGet = func(_ net.IP) ([]netlink.Route, error) {
		return []netlink.Route{{LinkIndex: 1}}, nil
	}
	dummyLink := &netlink.Dummy{}
	linkByIndex = func(_ int) (netlink.Link, error) {
		return dummyLink, nil
	}
	addrList = func(_ netlink.Link, _ int) ([]netlink.Addr, error) {
		return []netlink.Addr{{IPNet: &net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(32, 32)}}}, nil
	}

	addr, conn, err := LocalAddrForHost(net.IPv4(127, 0, 0, 1), 33434)
	if err != nil {
		t.Fatalf("LocalAddrForHost returned error: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	if !addr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("expected derived loopback IP, got %s", addr.IP)
	}
}

func TestLocalAddrFallsBackWhenNetlinkFails(t *testing.T) {
	originalRouteGet := routeGet
	defer func() { routeGet = originalRouteGet }()

	routeGet = func(_ net.IP) ([]netlink.Route, error) {
		return nil, errors.New("boom")
	}

	addr, conn, err := LocalAddrForHost(net.IPv4(127, 0, 0, 1), 33434)
	if err != nil {
		t.Fatalf("LocalAddrForHost returned error: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	if addr.IP == nil {
		t.Fatalf("expected a local address from dial fallback")
	}
}

func TestLocalAddrFallsBackOnNetlinkOverflow(t *testing.T) {
	originalRouteGet := routeGet
	defer func() { routeGet = originalRouteGet }()

	routeGet = func(_ net.IP) ([]netlink.Route, error) {
		return nil, syscall.EOVERFLOW
	}

	addr, conn, err := LocalAddrForHost(net.IPv4(127, 0, 0, 1), 33434)
	if err != nil {
		t.Fatalf("LocalAddrForHost returned error: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	if addr.IP == nil {
		t.Fatalf("expected a local address from dial fallback")
	}
}
