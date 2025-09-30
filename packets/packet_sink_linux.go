// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build linux

package packets

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// sinkLinux is an implementation of the packet sink interface for linux
type sinkLinux struct {
	sock    *os.File
	rawConn syscall.RawConn
}

var _ Sink = &sinkLinux{}

// NewSinkLinux returns a new sinkLinux implementing packet sink
func NewSinkLinux(addr netip.Addr) (Sink, error) {
	var domain, protocol, hdrincl int
	switch {
	case addr.Is4():
		domain = unix.AF_INET
		protocol = unix.IPPROTO_IP
		hdrincl = unix.IP_HDRINCL
	case addr.Is6():
		domain = unix.AF_INET6
		protocol = unix.IPPROTO_IPV6
		hdrincl = unix.IPV6_HDRINCL
	default:
		return nil, fmt.Errorf("SinkLinux supports only IPv4 or IPv6 addresses")
	}

	fd, err := unix.Socket(domain, unix.SOCK_RAW|unix.SOCK_NONBLOCK, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket: %w", err)
	}

	err = unix.SetsockoptInt(fd, protocol, hdrincl, 1)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to set header include option: %w", err)
	}

	sock := os.NewFile(uintptr(fd), "")
	rawConn, err := sock.SyscallConn()
	if err != nil {
		sock.Close()
		return nil, fmt.Errorf("failed to get raw connection: %w", err)
	}

	return &sinkLinux{
		sock:    sock,
		rawConn: rawConn,
	}, nil
}

// WriteTo writes the given packet (buffer starts at the IP layer) to addrPort.
func (p *sinkLinux) WriteTo(buf []byte, addr netip.AddrPort) error {
	sa, err := getSockAddr(addr.Addr())
	if err != nil {
		return err
	}

	writeErr := p.rawConn.Write(func(fd uintptr) bool {
		err = unix.Sendto(int(fd), buf, 0, sa)
		if err == nil {
			return true
		}

		return !(err == syscall.EAGAIN || err == syscall.EWOULDBLOCK)
	})

	return errors.Join(writeErr, err)
}

// Close closes the socket
func (p *sinkLinux) Close() error {
	return p.sock.Close()
}
