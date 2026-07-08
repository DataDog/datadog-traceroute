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
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/DataDog/datadog-traceroute/common"
)

const (
	pcapSnapLen     = 4096
	pcapReadTimeout = 100 * time.Millisecond
	pcapBufferSize  = 1024 * 1024 // 1 MB kernel BPF buffer
)

// PcapSource implements the Source interface using libpcap on macOS.
type PcapSource struct {
	handle   *pcap.Handle
	linkType layers.LinkType
	deadline time.Time
}

var _ Source = &PcapSource{}

var errNoNewPackets = &common.ReceiveProbeNoPktError{Err: fmt.Errorf("no new packets before timeout")}

// Close implements Source.
func (p *PcapSource) Close() error {
	if p.handle != nil {
		p.handle.Close()
		p.handle = nil
	}
	return nil
}

// Read implements Source. It returns one IP-layer packet (link-layer header stripped).
func (p *PcapSource) Read(buf []byte) (int, error) {
	for {
		if !p.deadline.IsZero() && time.Now().After(p.deadline) {
			return 0, errNoNewPackets
		}

		data, _, err := p.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			if !p.deadline.IsZero() && time.Now().After(p.deadline) {
				return 0, errNoNewPackets
			}
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("PcapSource Read failed: %w", err)
		}

		var payload []byte
		switch p.linkType {
		case layers.LinkTypeNull, layers.LinkTypeLoop:
			if len(data) < 4 {
				continue
			}
			payload = data[4:]
		case layers.LinkTypeEthernet:
			payload, err = stripEthernetHeader(data)
			if err != nil {
				return 0, err
			}
			if payload == nil {
				continue // non-IP packet, skip
			}
		default:
			return 0, fmt.Errorf("PcapSource Read: unsupported link type %v", p.linkType)
		}

		return copy(buf, payload), nil
	}
}

// SetReadDeadline implements Source.
func (p *PcapSource) SetReadDeadline(t time.Time) error {
	p.deadline = t
	return nil
}

// SetPacketFilter applies a BPF filter expression to the pcap handle.
func (p *PcapSource) SetPacketFilter(spec PacketFilterSpec) error {
	expr, err := filterSpecToExpr(spec)
	if err != nil {
		return err
	}
	return p.handle.SetBPFFilter(expr)
}

// filterSpecToExpr converts a PacketFilterSpec to a tcpdump filter expression.
func filterSpecToExpr(spec PacketFilterSpec) (string, error) {
	switch spec.FilterType {
	case FilterTypeICMP:
		return "icmp or icmp6", nil
	case FilterTypeUDP:
		return "icmp or icmp6 or udp", nil
	case FilterTypeTCP:
		return filterTCPExpr(spec.FilterConfig)
	case FilterTypeSYNACK:
		return "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack != 0", nil
	default:
		return "", fmt.Errorf("unsupported filter type %d", spec.FilterType)
	}
}

// filterTCPExpr builds a tcpdump expression that passes ICMP/ICMPv6 plus
// TCP traffic matching the given 4-tuple (src/dst addr+port).
func filterTCPExpr(cfg FilterConfig) (string, error) {
	if !cfg.Src.IsValid() || !cfg.Dst.IsValid() {
		return "", fmt.Errorf("FilterTypeTCP requires valid Src and Dst in FilterConfig")
	}
	return fmt.Sprintf(
		"icmp or icmp6 or (tcp and host %s and host %s and port %d and port %d)",
		cfg.Src.Addr(), cfg.Dst.Addr(), cfg.Src.Port(), cfg.Dst.Port(),
	), nil
}

func deviceForTarget(targetIp netip.Addr) (net.Interface, error) {
	// On macOS, net.Dial() to a loopback destination may return a non-loopback local address.
	// Find the loopback interface directly so we attach BPF to the correct interface.
	if targetIp.IsLoopback() {
		ifaces, err := net.Interfaces()
		if err != nil {
			return net.Interface{}, fmt.Errorf("deviceForTarget failed to get interfaces: %w", err)
		}
		// Look for the loopback interface (typically "lo0" on macOS)
		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback != 0 {
				return iface, nil
			}
		}
		return net.Interface{}, fmt.Errorf("deviceForTarget couldn't find loopback interface for loopback target")
	}

	conn, err := net.Dial("udp", net.JoinHostPort(targetIp.String(), "53"))
	if err != nil {
		return net.Interface{}, fmt.Errorf("deviceForTarget failed to dial UDP: %w", err)
	}
	defer conn.Close()
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

// NewBpfDevice returns a new Source using libpcap for packet capture.
func NewBpfDevice(targetIp netip.Addr) (Source, error) {
	iface, err := deviceForTarget(targetIp)
	if err != nil {
		return nil, fmt.Errorf("NewBpfDevice failed to find interface for target: %w", err)
	}

	inactive, err := pcap.NewInactiveHandle(iface.Name)
	if err != nil {
		return nil, fmt.Errorf("NewBpfDevice failed to create pcap handle: %w", err)
	}
	if err := inactive.SetSnapLen(pcapSnapLen); err != nil {
		inactive.CleanUp()
		return nil, fmt.Errorf("NewBpfDevice failed to set snap len: %w", err)
	}
	if err := inactive.SetPromisc(false); err != nil {
		inactive.CleanUp()
		return nil, fmt.Errorf("NewBpfDevice failed to set promisc: %w", err)
	}
	if err := inactive.SetTimeout(pcapReadTimeout); err != nil {
		inactive.CleanUp()
		return nil, fmt.Errorf("NewBpfDevice failed to set timeout: %w", err)
	}
	if err := inactive.SetImmediateMode(true); err != nil {
		inactive.CleanUp()
		return nil, fmt.Errorf("NewBpfDevice failed to set immediate mode: %w", err)
	}
	if err := inactive.SetBufferSize(pcapBufferSize); err != nil {
		inactive.CleanUp()
		return nil, fmt.Errorf("NewBpfDevice failed to set buffer size: %w", err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		inactive.CleanUp()
		return nil, fmt.Errorf("NewBpfDevice failed to activate pcap handle: %w", err)
	}

	// Verify the link type is something we can handle
	lt := handle.LinkType()
	if lt != layers.LinkTypeNull && lt != layers.LinkTypeLoop && lt != layers.LinkTypeEthernet {
		handle.Close()
		return nil, fmt.Errorf("NewBpfDevice: unsupported link type %v on %s", lt, iface.Name)
	}

	return &PcapSource{
		handle:   handle,
		linkType: handle.LinkType(),
	}, nil
}
