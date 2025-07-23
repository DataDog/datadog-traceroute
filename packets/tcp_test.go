// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build test && linux && linux_bpf

package packets

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type tcpTestCase struct {
	filterConfig  func(server, client netip.AddrPort) TCP4FilterConfig
	shouldCapture bool
}

func doTestCase(t *testing.T, tc tcpTestCase) {
	// we use bound ports on the server and the client so this should be safe to parallelize
	t.Parallel()

	server := NewTCPServerOnAddress("127.0.0.42:0", func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Write([]byte("foo\n"))
		GracefulCloseTCP(c)
	})
	t.Cleanup(server.Shutdown)
	require.NoError(t, server.Run())

	dialer := net.Dialer{
		Timeout: time.Minute,
		LocalAddr: &net.TCPAddr{
			// make it different from the server IP
			IP: net.ParseIP("127.0.0.43"),
		},
	}

	conn, err := dialer.Dial("tcp", server.Address())
	require.NoError(t, err)
	defer GracefulCloseTCP(conn)

	serverAddrPort, err := netip.ParseAddrPort(server.Address())
	require.NoError(t, err)
	clientAddrPort, err := netip.ParseAddrPort(conn.LocalAddr().String())
	require.NoError(t, err)

	cfg := tc.filterConfig(serverAddrPort, clientAddrPort)
	filter, err := cfg.GenerateTCP4Filter()
	require.NoError(t, err)

	lc := &net.ListenConfig{
		Control: func(_network, _address string, c syscall.RawConn) error {
			err := SetBPFAndDrain(c, filter)
			require.NoError(t, err)
			return err
		},
	}

	rawConn, err := MakeRawConn(context.Background(), lc, "ip:tcp", clientAddrPort.Addr())
	require.NoError(t, err)

	conn.Write([]byte("bar\n"))

	buffer := make([]byte, 1024)

	rawConn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	n, addr, err := rawConn.ReadFromIP(buffer)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		// ErrDeadlineExceeded is what the test checks for, so we should only blow up on real errors
		require.NoError(t, err)
		require.NotZero(t, n)
	}

	hasCaptured := !errors.Is(err, os.ErrDeadlineExceeded)
	if tc.shouldCapture {
		require.True(t, hasCaptured, "expected to see a packet, but found nothing")
		require.Equal(t, addr.IP, net.IP(cfg.Src.Addr().AsSlice()))
	} else {
		require.False(t, hasCaptured, "expected not to see a packet, but found one from %s", addr)
	}

}
func TestTCPFilterMatch(t *testing.T) {
	doTestCase(t, tcpTestCase{
		filterConfig: func(server, client netip.AddrPort) TCP4FilterConfig {
			return TCP4FilterConfig{Src: server, Dst: client}
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
		filterConfig: func(server, client netip.AddrPort) TCP4FilterConfig {
			return TCP4FilterConfig{Src: mangleIP(server), Dst: client}
		},
		shouldCapture: false,
	})
}

func TestTCPFilterBadServerPort(t *testing.T) {
	doTestCase(t, tcpTestCase{
		filterConfig: func(server, client netip.AddrPort) TCP4FilterConfig {
			return TCP4FilterConfig{Src: manglePort(server), Dst: client}
		},
		shouldCapture: false,
	})
}

func TestTCPFilterBadClientIP(t *testing.T) {
	doTestCase(t, tcpTestCase{
		filterConfig: func(server, client netip.AddrPort) TCP4FilterConfig {
			return TCP4FilterConfig{Src: server, Dst: mangleIP(client)}
		},
		shouldCapture: false,
	})
}

func TestTCPFilterBadClientPort(t *testing.T) {
	doTestCase(t, tcpTestCase{
		filterConfig: func(server, client netip.AddrPort) TCP4FilterConfig {
			return TCP4FilterConfig{Src: server, Dst: manglePort(client)}
		},
		shouldCapture: false,
	})
}

// TCPServer is a simple TCP server for use in tests
type TCPServer struct {
	address   string
	Network   string
	onMessage func(c net.Conn)
	ln        net.Listener
}

// NewTCPServer creates a TCPServer using the provided function for newly accepted connections.
// It defaults to listening on an ephemeral port on 127.0.0.1
func NewTCPServer(onMessage func(c net.Conn)) *TCPServer {
	return NewTCPServerOnAddress("127.0.0.1:0", onMessage)
}

// NewTCPServerOnAddress creates a TCPServer using the provided address.
func NewTCPServerOnAddress(addr string, onMessage func(c net.Conn)) *TCPServer {
	return &TCPServer{
		address:   addr,
		onMessage: onMessage,
	}
}

// Address returns the address of the server. This should be called after Run.
func (t *TCPServer) Address() string {
	return t.address
}

// Addr is the raw net.Addr of the listener
func (t *TCPServer) Addr() net.Addr {
	return t.ln.Addr()
}

// Run starts the TCP server
func (t *TCPServer) Run() error {
	networkType := "tcp"
	if t.Network != "" {
		networkType = t.Network
	}
	ln, err := net.Listen(networkType, t.address)
	if err != nil {
		return err
	}
	t.ln = ln
	t.address = ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			err = SetTestDeadline(conn)
			if err != nil {
				return
			}
			go t.onMessage(conn)
		}
	}()

	return nil
}

// Dial creates a TCP connection to the server, and sets reasonable timeouts
func (t *TCPServer) Dial() (net.Conn, error) {
	return DialTCP("tcp", t.Address())
}

// DialTCP creates a connection to the specified address, and sets reasonable timeouts for TCP
func DialTCP(network, address string) (net.Conn, error) {
	conn, err := net.DialTimeout(network, address, time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s: %w", address, err)
	}
	err = SetTestDeadline(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// Shutdown stops the TCP server
func (t *TCPServer) Shutdown() {
	if t.ln != nil {
		_ = t.ln.Close()
		t.ln = nil
	}
}

// SetTestDeadline prevents connection reads/writes from blocking the test indefinitely
func SetTestDeadline(conn net.Conn) error {
	// any test in the tracer suite should conclude in less than a minute (normally a couple seconds)
	return conn.SetDeadline(time.Now().Add(time.Minute))
}

// GracefulCloseTCP closes a connection after making sure all data has been sent/read
// It first shuts down the write end, then reads until EOF, then closes the connection
// https://blog.netherlabs.nl/articles/2009/01/18/the-ultimate-so_linger-page-or-why-is-my-tcp-not-reliable
func GracefulCloseTCP(conn net.Conn) error {
	tcpConn := conn.(*net.TCPConn)

	shutdownErr := tcpConn.CloseWrite()
	_, readErr := io.Copy(io.Discard, tcpConn)
	closeErr := tcpConn.Close()
	return errors.Join(shutdownErr, readErr, closeErr)
}
