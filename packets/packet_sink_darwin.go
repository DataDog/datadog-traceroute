// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build darwin

package packets

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

// sinkDarwin is an implementation of the packet Sink interface for darwin
type sinkDarwin struct {
	fd       int
	writeBuf []byte
}

var _ Sink = &sinkDarwin{}

// NewSinkDarwin returns a new sinkDarwin implementing packet sink
func NewSinkDarwin(addr netip.Addr) (Sink, error) {
	var domain, protocol int
	switch {
	case addr.Is4():
		domain = unix.AF_INET
		protocol = unix.IPPROTO_IP
	case addr.Is6():
		domain = unix.AF_INET6
		protocol = unix.IPPROTO_IPV6
	default:
		return nil, fmt.Errorf("SinkDarwin supports only IPv4 or IPv6 addresses")
	}

	fd, err := unix.Socket(domain, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket: %w", err)
	}

	// darwin only supports IP_HDRINCL for IPv4...
	if addr.Is4() {
		err = unix.SetsockoptInt(fd, protocol, unix.IP_HDRINCL, 1)
		if err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("failed to set header include option: %w", err)
		}
	}

	return &sinkDarwin{
		fd:       fd,
		writeBuf: make([]byte, 4096),
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
		// set the TTL via IPV6_HOPLIMIT
		err = unix.SetsockoptInt(p.fd, unix.IPPROTO_IPV6, unix.IPV6_HOPLIMIT, int(ttl))
		if err != nil {
			return fmt.Errorf("failed to set IPV6_HOPLIMIT: %w", err)
		}
	default:
		return fmt.Errorf("invalid address family %s", addr)
	}

	err = unix.Sendto(p.fd, sendBuf, 0, sa)

	return err
}

// Close closes the socket
func (p *sinkDarwin) Close() error {
	fd := p.fd
	p.fd = 0
	return unix.Close(fd)
}
