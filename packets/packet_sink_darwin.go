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
	"sync"
	"syscall"

	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// sinkDarwin is an implementation of the packet Sink interface for darwin
type sinkDarwin struct {
	sock     *os.File
	rawConn  syscall.RawConn
	writeBuf []byte

	// ipv6Once guards lazy creation of the IPv6 socket. On macOS, IPPROTO_RAW
	// doesn't support sending IPv6 packets (the protocol in the IP packet
	// will be set to 255), so we need to make a protocol-specific socket.
	ipv6Once   sync.Once
	ipv6Proto  int
	ipv6Err    error
}

var _ Sink = &sinkDarwin{}

// NewSinkDarwin returns a new sinkDarwin implementing packet sink
func NewSinkDarwin(addr netip.Addr) (Sink, error) {
	s := &sinkDarwin{
		writeBuf: make([]byte, 4096),
	}

	switch {
	case addr.Is4():
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
		if err != nil {
			return nil, fmt.Errorf("failed to create raw socket: %w", err)
		}
		err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
		if err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("failed to set header include option: %w", err)
		}
		sock := os.NewFile(uintptr(fd), "")
		rawConn, err := sock.SyscallConn()
		if err != nil {
			sock.Close()
			return nil, fmt.Errorf("failed to create SyscallConn(): %w", err)
		}
		s.sock = sock
		s.rawConn = rawConn
	case addr.Is6():
		// Defer socket creation to WriteTo — macOS does not support
		// IPPROTO_RAW for IPv6 sendmsg with ancillary data, so we need
		// the actual transport protocol from the packet's NextHeader field.
		// Socket created lazily in ensureIPv6Socket.
	default:
		return nil, fmt.Errorf("SinkDarwin supports only IPv4 or IPv6 addresses")
	}

	return s, nil
}

const ipv6HeaderSize = 40

// ensureIPv6Socket lazily creates the IPv6 raw socket using the transport
// protocol from the IPv6 NextHeader field.
func (p *sinkDarwin) ensureIPv6Socket(nextHeader int) error {
	p.ipv6Once.Do(func() {
		p.ipv6Proto = nextHeader
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_RAW)
		if err != nil {
			p.ipv6Err = fmt.Errorf("failed to create IPv6 raw socket (proto %d): %w", nextHeader, err)
			return
		}
		sock := os.NewFile(uintptr(fd), "")
		rawConn, err := sock.SyscallConn()
		if err != nil {
			sock.Close()
			p.ipv6Err = fmt.Errorf("failed to create SyscallConn(): %w", err)
			return
		}
		p.sock = sock
		p.rawConn = rawConn
	})
	if p.ipv6Err == nil && nextHeader != p.ipv6Proto {
		return fmt.Errorf("IPv6 socket bound to protocol %d, but got packet with NextHeader %d; only one protocol at a time is supported", p.ipv6Proto, nextHeader)
	}
	return p.ipv6Err
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
	var oob []byte
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
		if len(buf) < ipv6HeaderSize {
			return fmt.Errorf("sinkDarwin WriteTo: packet too small for IPv6 header")
		}
		// Read NextHeader before stripping, so we can create the right socket
		nextHeader := int(buf[6])
		if err := p.ensureIPv6Socket(nextHeader); err != nil {
			return err
		}
		// IPv6: darwin has no IPV6_HDRINCL, so we need to strip the IPv6 header
		var ttl uint8
		sendBuf, ttl, err = stripIPv6Header(buf)
		if err != nil {
			return fmt.Errorf("failed to strip IPv6 header: %w", err)
		}
		control := ipv6.ControlMessage{
			HopLimit: int(ttl),
		}
		oob = control.Marshal()
	default:
		return fmt.Errorf("invalid address family %s", addr)
	}

	writeErr := p.rawConn.Write(func(fd uintptr) bool {
		if oob != nil {
			err = unix.Sendmsg(int(fd), sendBuf, oob, sa, 0)
		} else {
			err = unix.Sendto(int(fd), sendBuf, 0, sa)
		}
		if err == nil {
			return true
		}

		return !(err == syscall.EAGAIN || err == syscall.EWOULDBLOCK)
	})

	return errors.Join(writeErr, err)
}

// Close closes the socket
func (p *sinkDarwin) Close() error {
	if p.sock != nil {
		return p.sock.Close()
	}
	return nil
}
