// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build test && linux

package packets

import (
	"bufio"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/DataDog/datadog-traceroute/testutils"
)

type tcpTestCase struct {
	filterConfig  func(server, client netip.AddrPort) TCPFilterConfig
	shouldCapture bool
}

func makeNetns() (netns.NsHandle, error) {
	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save the current network namespace
	origns, err := netns.Get()
	defer origns.Close()
	if err != nil {
		return netns.None(), err
	}
	// Switch back to the original namespace when we are done
	defer netns.Set(origns)

	// Create a new network namespace
	newns, err := netns.New()
	if err != nil {
		return netns.None(), err
	}

	// get the loopback interface
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return netns.None(), err
	}

	// enable the loopback interface (it's down by default)
	err = netlink.LinkSetUp(lo)
	if err != nil {
		return netns.None(), err
	}

	return newns, err
}

func doTestCase(t *testing.T, tc tcpTestCase) {
	// we use a separate netns for each test so this is safe to parallelize
	t.Parallel()

	testns, err := makeNetns()
	require.NoError(t, err)
	defer testns.Close()

	server := testutils.NewTCPServerOnAddress("127.0.0.42:0", func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Write([]byte("foo\n"))
		testutils.GracefulCloseTCP(c)
	})
	t.Cleanup(server.Shutdown)
	// we only need testns to be active when we call bind()/listen()
	err = testutils.WithNS(testns, server.Listen)
	require.NoError(t, err)
	server.StartAccepting()

	dialer := net.Dialer{
		Timeout: time.Minute,
		LocalAddr: &net.TCPAddr{
			// make it different from the server IP
			IP: net.ParseIP("127.0.0.43"),
		},
	}

	var conn net.Conn
	err = testutils.WithNS(testns, func() error {
		nsConn, nsErr := dialer.Dial("tcp", server.Address())
		conn = nsConn
		return nsErr
	})
	require.NoError(t, err)
	defer testutils.GracefulCloseTCP(conn)

	serverAddrPort, err := netip.ParseAddrPort(server.Address())
	require.NoError(t, err)
	clientAddrPort, err := netip.ParseAddrPort(conn.LocalAddr().String())
	require.NoError(t, err)

	cfg := tc.filterConfig(serverAddrPort, clientAddrPort)

	var source Source
	testutils.WithNS(testns, func() error {
		nsSource, nsErr := NewAFPacketSource()
		source = nsSource
		return nsErr
	})
	err = source.SetPacketFilter(PacketFilterSpec{
		FilterType:      FilterTypeTCP,
		TCPFilterConfig: cfg,
	})
	require.NoError(t, err)

	conn.Write([]byte("bar\n"))

	buffer := make([]byte, 1024)
	parser := NewFrameParser()

	source.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	err = ReadAndParse(source, buffer, parser)

	if !errors.Is(err, os.ErrDeadlineExceeded) {
		// ErrDeadlineExceeded is what the test checks for, so we should only blow up on real errors
		require.NoError(t, err)
	}

	hasCaptured := !errors.Is(err, os.ErrDeadlineExceeded)
	if tc.shouldCapture {
		require.True(t, hasCaptured, "expected to see a packet, but found nothing")
		require.Equal(t, layers.LayerTypeIPv4, parser.GetIPLayer())
		require.Equal(t, net.IP(cfg.Src.Addr().AsSlice()), parser.IP4.SrcIP)
	} else {
		require.False(t, hasCaptured, "expected not to see a packet, but found one from %s", parser.IP4.SrcIP)
	}

}
func TestTCPFilterMatch(t *testing.T) {
	doTestCase(t, tcpTestCase{
		filterConfig: func(server, client netip.AddrPort) TCPFilterConfig {
			return TCPFilterConfig{Src: server, Dst: client}
		},
		shouldCapture: true,
	})
}

func mangleIP(ap netip.AddrPort) netip.AddrPort {
	reservedIP := netip.MustParseAddr("233.252.0.0")
	return netip.AddrPortFrom(reservedIP, ap.Port())
}
func manglePort(ap netip.AddrPort) netip.AddrPort {
	const reservedPort = 47
	return netip.AddrPortFrom(ap.Addr(), reservedPort)
}

func TestTCPFilterBadServerIP(t *testing.T) {
	doTestCase(t, tcpTestCase{
		filterConfig: func(server, client netip.AddrPort) TCPFilterConfig {
			return TCPFilterConfig{Src: mangleIP(server), Dst: client}
		},
		shouldCapture: false,
	})
}

func TestTCPFilterBadServerPort(t *testing.T) {
	doTestCase(t, tcpTestCase{
		filterConfig: func(server, client netip.AddrPort) TCPFilterConfig {
			return TCPFilterConfig{Src: manglePort(server), Dst: client}
		},
		shouldCapture: false,
	})
}

func TestTCPFilterBadClientIP(t *testing.T) {
	doTestCase(t, tcpTestCase{
		filterConfig: func(server, client netip.AddrPort) TCPFilterConfig {
			return TCPFilterConfig{Src: server, Dst: mangleIP(client)}
		},
		shouldCapture: false,
	})
}

func TestTCPFilterBadClientPort(t *testing.T) {
	doTestCase(t, tcpTestCase{
		filterConfig: func(server, client netip.AddrPort) TCPFilterConfig {
			return TCPFilterConfig{Src: server, Dst: manglePort(client)}
		},
		shouldCapture: false,
	})
}
