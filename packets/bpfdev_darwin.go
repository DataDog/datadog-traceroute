// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build darwin

package packets

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
	"unsafe"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/log"
	"golang.org/x/sys/unix"
)

// Note: the BSD docs say BPF headers are aligned along the machine's word boundary.
// This isn't true anymore for 64 bit systems, the alignment is still 4 bytes.
// So it's not aligned by the size of a pointer but rather the alignment of the BpfHdr struct here.
const bpfSize = int(unsafe.Alignof(unix.BpfHdr{}))

func bpfAlign(x int) int {
	const mask = bpfSize - 1
	return (x + mask) &^ mask
}

// maxBpfDevices is the hard limit MacOS has for bpf devices
const maxBpfDevices = 256

func pickBpfDevice() (int, error) {
	for i := 0; i < maxBpfDevices; i++ {
		name := fmt.Sprintf("/dev/bpf%d", i)
		fd, err := unix.Open(name, unix.O_RDWR, 0)
		if err == unix.EBUSY {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("pickBpfDevice failed to open %s: %w", name, err)
		}

		return fd, nil
	}

	return 0, fmt.Errorf("pickBpfDevice tried all %d bpf devices, were all busy", maxBpfDevices)
}

type BpfDevice struct {
	fd       int
	deadline time.Time
	readBuf  []byte
	pktBuf   []byte
}

// Close implements Source.
func (b *BpfDevice) Close() error {
	if b.fd == 0 {
		return nil
	}
	fd := b.fd
	b.fd = 0
	return unix.Close(fd)
}

var _ Source = &BpfDevice{}

func (b *BpfDevice) hasNextPacket() bool {
	return len(b.pktBuf) > 0
}

var errNoNewPackets = &common.ReceiveProbeNoPktError{Err: fmt.Errorf("no new packets before timeout")}

func (b *BpfDevice) readPackets() error {
	timeout := getReadTimeout(b.deadline)
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	err := syscall.SetBpfTimeout(b.fd, &tv)
	if err != nil {
		return fmt.Errorf("readPackets failed toSetBpfTimeout: %w")
	}
	n, err := unix.Read(b.fd, b.readBuf)
	if err == unix.EINTR {
		return errNoNewPackets
	}
	if err != nil {
		return fmt.Errorf("readPackets failed to Read: %w", err)
	}
	b.pktBuf = b.readBuf[:n]
	if n == 0 {
		return errNoNewPackets
	}

	return nil
}

// nextPacket returns the next packet, including ethernet header (but not the darwin BpfHdr)
func (b *BpfDevice) nextPacket() ([]byte, error) {
	if len(b.pktBuf) < int(unsafe.Sizeof(unix.BpfHdr{})) {
		return nil, fmt.Errorf("nextPacket: buffer size=%d is too small", len(b.pktBuf))
	}
	header := (*unix.BpfHdr)(unsafe.Pointer(&b.pktBuf[0]))
	start := int(header.Hdrlen)
	pktFinish := start + int(header.Caplen)
	dataFinish := bpfAlign(pktFinish)
	if len(b.pktBuf) < pktFinish {
		log.Tracef("CRASHING")
		return nil, fmt.Errorf("nextPacket: buffer size=%d is smaller than expected size %d", len(b.pktBuf), pktFinish)
	}

	packet := b.pktBuf[start:pktFinish]
	if len(b.pktBuf) > dataFinish {
		b.pktBuf = b.pktBuf[dataFinish:]
	} else {
		b.pktBuf = nil
	}

	return packet, nil
}

// Read implements Source.
func (b *BpfDevice) Read(buf []byte) (int, error) {
	var payload []byte
	for payload == nil {
		if !b.hasNextPacket() {
			err := b.readPackets()
			if err != nil {
				return 0, err
			}
		}

		ethFrame, err := b.nextPacket()
		if err != nil {
			return 0, err
		}
		payload, err = stripEthernetHeader(ethFrame)
		if err != nil {
			return 0, err
		}
	}

	return copy(buf, payload), nil
}

// SetReadDeadline implements Source.
func (b *BpfDevice) SetReadDeadline(t time.Time) error {
	b.deadline = t
	return nil
}

func deviceForTarget(targetIp netip.Addr) (net.Interface, error) {
	conn, err := net.Dial("udp", net.JoinHostPort(targetIp.String(), "53"))
	if err != nil {
		return net.Interface{}, fmt.Errorf("deviceForTarget failed to dial UDP: %w", err)
	}
	laddr := conn.LocalAddr().(*net.UDPAddr)
	ifaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, fmt.Errorf("deviceForTarget failed to get interfaces: %w", err)
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return net.Interface{}, fmt.Errorf("deviceForTarget failed to get interface addrs: %w", err)
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipnet.IP.Equal(laddr.IP) {
				return iface, nil
			}
		}
	}

	return net.Interface{}, fmt.Errorf("deviceForTarget couldn't find a matching interface")
}

func NewBpfDevice(targetIp netip.Addr) (Source, error) {
	iface, err := deviceForTarget(targetIp)
	if err != nil {
		return nil, fmt.Errorf("NewBpfDevice failed to find interface for target: %w", err)
	}

	fd, err := pickBpfDevice()
	if err != nil {
		return nil, err
	}
	err = syscall.SetBpfImmediate(fd, 1)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("NewBpfDevice failed to SetBpfImmediate: %w", err)
	}

	err = syscall.SetBpfInterface(fd, iface.Name)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("NewBpfDevice failed to SetBpfInterface: %w", err)
	}

	return &BpfDevice{
		fd:      fd,
		readBuf: make([]byte, 4096),
		// no packets yet
		pktBuf: nil,
	}, nil
}
