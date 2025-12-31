// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build darwin

package packets

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// sinkDarwin is an implementation of the packet Sink interface for darwin
type sinkDarwin struct {
	sock     *os.File
	rawConn  syscall.RawConn
	writeBuf []byte
	isIPv6   bool
}

var _ Sink = &sinkDarwin{}

// NewSinkDarwin returns a new sinkDarwin implementing packet sink
// protocol is the IP protocol number (e.g., 17 for UDP, 6 for TCP, 58 for ICMPv6)
// For IPv6, this is used as the socket protocol since Darwin doesn't support IPV6_HDRINCL.
func NewSinkDarwin(addr netip.Addr, protocol int) (Sink, error) {
	var domain, sockOptLevel int
	var sockProtocol int
	isIPv6 := false

	switch {
	case addr.Is4():
		domain = unix.AF_INET
		sockOptLevel = unix.IPPROTO_IP
		sockProtocol = unix.IPPROTO_RAW
	case addr.Is6():
		domain = unix.AF_INET6
		sockOptLevel = unix.IPPROTO_IPV6
		// For IPv6 on Darwin, we must use the actual protocol number
		// because there's no IPV6_HDRINCL option. The kernel builds the
		// IPv6 header and uses the socket protocol as NextHeader.
		sockProtocol = protocol
		isIPv6 = true
	default:
		return nil, fmt.Errorf("SinkDarwin supports only IPv4 or IPv6 addresses")
	}

	fd, err := unix.Socket(domain, unix.SOCK_RAW, sockProtocol)
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket: %w", err)
	}

	// darwin only supports IP_HDRINCL for IPv4...
	if addr.Is4() {
		err = unix.SetsockoptInt(fd, sockOptLevel, unix.IP_HDRINCL, 1)
		if err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("failed to set header include option: %w", err)
		}
	}

	sock := os.NewFile(uintptr(fd), "")
	rawConn, err := sock.SyscallConn()
	if err != nil {
		sock.Close()
		return nil, fmt.Errorf("failed to create SyscallConn(): %w", err)
	}

	return &sinkDarwin{
		sock:     sock,
		rawConn:  rawConn,
		writeBuf: make([]byte, 4096),
		isIPv6:   isIPv6,
	}, nil
}

// updateNtohs16 replaces network-order uint16 with host-order, in-place
func updateNtohs16(num []byte) {
	val := binary.BigEndian.Uint16(num)
	binary.NativeEndian.PutUint16(num, val)
}

// WriteTo writes the given packet (buffer starts at the IP layer) to addrPort.
func (p *sinkDarwin) WriteTo(buf []byte, addr netip.AddrPort) error {
	sa, err := getSockAddr(addr.Addr())
	if err != nil {
		return err
	}

	var sendBuf []byte
	switch {
	case addr.Addr().Is4():
		if len(buf) > len(p.writeBuf) {
			return fmt.Errorf("sinkDarwin WriteTo failed because packet is too large (couldn't copy)")
		}
		// IPv4: send it using IP_HDRINCL
		sendBuf = p.writeBuf[:len(buf)]
		copy(sendBuf, buf)
		const ipv4MinSize = 20
		if len(sendBuf) < ipv4MinSize {
			return fmt.Errorf("sinkDarwin WriteTo failed because packet is smaller than ipv4 header")
		}
		// you can't send it as-is, it needs a quirky modification:
		// https://cseweb.ucsd.edu/~braghava/notes/freebsd-sockets.txt
		// "ip_len and ip_off must be in host byte order"
		const ip_lenOffset = 2
		const ip_offOffset = 6
		updateNtohs16(sendBuf[ip_lenOffset : ip_lenOffset+2])
		updateNtohs16(sendBuf[ip_offOffset : ip_offOffset+2])
	case addr.Addr().Is6():
		// IPv6: darwin has no IPV6_HDRINCL, so we need to strip the IPv6 header
		var ttl uint8
		sendBuf, ttl, err = stripIPv6Header(buf)
		if err != nil {
			return fmt.Errorf("failed to strip IPv6 header: %w", err)
		}
		var controlErr error
		// set the hop limit via IPV6_UNICAST_HOPS (not IPV6_HOPLIMIT which is for receiving)
		err = p.rawConn.Control(func(fd uintptr) {
			controlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, int(ttl))
		})
		if err != nil {
			return fmt.Errorf("failed to call Control() for IPV6_UNICAST_HOPS: %w", controlErr)
		}
		if controlErr != nil {
			return fmt.Errorf("failed to set IPV6_UNICAST_HOPS: %w", controlErr)
		}
	default:
		return fmt.Errorf("invalid address family %s", addr)
	}

	writeErr := p.rawConn.Write(func(fd uintptr) bool {
		err = unix.Sendto(int(fd), sendBuf, 0, sa)
		if err == nil {
			return true
		}

		return !(err == syscall.EAGAIN || err == syscall.EWOULDBLOCK)
	})

	return errors.Join(writeErr, err)
}

// Close closes the socket
func (p *sinkDarwin) Close() error {
	return p.sock.Close()
}
