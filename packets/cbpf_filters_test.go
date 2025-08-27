// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package packets

import (
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/bpf"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeEth(t *testing.T, ethType layers.EthernetType) *layers.Ethernet {
	src, err := net.ParseMAC("00:00:5e:00:53:01")
	require.NoError(t, err)
	dst, err := net.ParseMAC("00:00:5e:00:53:02")
	require.NoError(t, err)

	return &layers.Ethernet{
		SrcMAC:       src,
		DstMAC:       dst,
		EthernetType: ethType,
	}
}

func makeTcpPayload(t *testing.T) []byte {
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(345),
		DstPort: layers.TCPPort(678),
		Seq:     1234,
		Ack:     5678,
		SYN:     true,
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths: true,
	}
	err := gopacket.SerializeLayers(buf, opts, tcp, gopacket.Payload("hey"))
	require.NoError(t, err)

	return buf.Bytes()
}

func makeIcmp4Packet(t *testing.T) []byte {
	tcpBytes := makeTcpPayload(t)[:8]

	eth := makeEth(t, layers.EthernetTypeIPv4)
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      123,
		SrcIP:    net.ParseIP("127.0.0.1"),
		DstIP:    net.ParseIP("127.0.0.2"),
		Id:       41821,
		Protocol: layers.IPProtocolICMPv4,
	}
	icmp4 := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeTimeExceeded, layers.ICMPv4CodeTTLExceeded),
	}
	payload := gopacket.Payload(tcpBytes)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buf, opts, eth, ip4, icmp4, payload)
	require.NoError(t, err)
	return buf.Bytes()
}

func makeIcmp6Packet(t *testing.T) []byte {
	tcpBytes := makeTcpPayload(t)

	eth := makeEth(t, layers.EthernetTypeIPv6)
	ip6 := &layers.IPv6{
		Version:    6,
		SrcIP:      net.ParseIP("::1"),
		DstIP:      net.ParseIP("::1"),
		NextHeader: layers.IPProtocolICMPv6,
	}
	icmp6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeTimeExceeded, layers.ICMPv6CodeHopLimitExceeded),
	}
	require.NoError(t, icmp6.SetNetworkLayerForChecksum(ip6))
	payload := gopacket.Payload(tcpBytes)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buf, opts, eth, ip6, icmp6, payload)
	require.NoError(t, err)
	return buf.Bytes()
}

func makeUdp4Packet(t *testing.T) []byte {
	eth := makeEth(t, layers.EthernetTypeIPv4)
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      123,
		SrcIP:    net.ParseIP("127.0.0.1"),
		DstIP:    net.ParseIP("127.0.0.2"),
		Id:       41821,
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: 123,
		DstPort: 456,
	}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip4))
	payload := gopacket.Payload("hello")

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buf, opts, eth, ip4, udp, payload)
	require.NoError(t, err)
	return buf.Bytes()
}

func makeUdp6Packet(t *testing.T) []byte {
	eth := makeEth(t, layers.EthernetTypeIPv6)
	ip6 := &layers.IPv6{
		Version:    6,
		SrcIP:      net.ParseIP("::1"),
		DstIP:      net.ParseIP("::1"),
		NextHeader: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: 123,
		DstPort: 456,
	}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip6))
	payload := gopacket.Payload("hello")

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buf, opts, eth, ip6, udp, payload)
	require.NoError(t, err)
	return buf.Bytes()
}

func makeTcp4SynPacket(t *testing.T) []byte {
	eth := makeEth(t, layers.EthernetTypeIPv4)
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      123,
		SrcIP:    net.ParseIP("127.0.0.1"),
		DstIP:    net.ParseIP("127.0.0.2"),
		Id:       41821,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(345),
		DstPort: layers.TCPPort(678),
		Seq:     1234,
		Ack:     5678,
		SYN:     true,
	}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip4))
	payload := gopacket.Payload("hello")

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buf, opts, eth, ip4, tcp, payload)
	require.NoError(t, err)
	return buf.Bytes()
}

func makeTcp4SynAckPacket(t *testing.T) []byte {
	eth := makeEth(t, layers.EthernetTypeIPv4)
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      123,
		SrcIP:    net.ParseIP("127.0.0.1"),
		DstIP:    net.ParseIP("127.0.0.2"),
		Id:       41821,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(345),
		DstPort: layers.TCPPort(678),
		Seq:     1234,
		Ack:     5678,
		SYN:     true,
		ACK:     true,
	}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip4))
	payload := gopacket.Payload("hello")

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buf, opts, eth, ip4, tcp, payload)
	require.NoError(t, err)
	return buf.Bytes()
}

func runClassicBpf(t *testing.T, bpfRaw []bpf.RawInstruction, packet []byte) int {
	bpfProg, ok := bpf.Disassemble(bpfRaw)
	require.True(t, ok)
	vm, err := bpf.NewVM(bpfProg)
	require.NoError(t, err)

	ret, err := vm.Run(packet)
	require.NoError(t, err)
	return ret
}

func TestClassicBPFFilters(t *testing.T) {
	type packetDef struct {
		name   string
		packet []byte
	}
	icmp4 := packetDef{"icmp4", makeIcmp4Packet(t)}
	icmp6 := packetDef{"icmp6", makeIcmp6Packet(t)}
	udp4 := packetDef{"udp4", makeUdp4Packet(t)}
	udp6 := packetDef{"udp6", makeUdp6Packet(t)}
	tcp4Syn := packetDef{"tcp4Syn", makeTcp4SynPacket(t)}
	tcp4Synack := packetDef{"tcp4Synack", makeTcp4SynAckPacket(t)}

	tcp4TupleFilter, err := FilterConfig{
		Src: netip.MustParseAddrPort("127.0.0.1:345"),
		Dst: netip.MustParseAddrPort("127.0.0.2:678"),
	}.GenerateTCP4Filter()
	require.NoError(t, err)

	type packetCase struct {
		packetDef     packetDef
		shouldCapture bool
	}
	testCases := []struct {
		name     string
		program  []bpf.RawInstruction
		expected []packetCase
	}{
		{
			name:    "drop all filter",
			program: dropAllFilter,
			expected: []packetCase{
				{icmp4, false},
				{icmp6, false},
				{udp4, false},
				{udp6, false},
				{tcp4Syn, false},
				{tcp4Synack, false},
			},
		},
		{
			name:    "icmp filter",
			program: icmpFilter,
			expected: []packetCase{
				{icmp4, true},
				{icmp6, true},
				{udp4, false},
				{udp6, false},
				{tcp4Syn, false},
				{tcp4Synack, false},
			},
		},
		{
			name:    "udp filter",
			program: udpFilter,
			expected: []packetCase{
				{icmp4, true},
				{icmp6, true},
				{udp4, true},
				{udp6, true},
				{tcp4Syn, false},
				{tcp4Synack, false},
			},
		},
		{
			name:    "tcp tuple filter",
			program: tcp4TupleFilter,
			expected: []packetCase{
				{icmp4, true},
				{icmp6, false},
				{udp4, false},
				{udp6, false},
				{tcp4Syn, true},
				{tcp4Synack, true},
			},
		},
		{
			name:    "tcp synack filter",
			program: tcpSynackFilter,
			expected: []packetCase{
				{icmp4, false},
				{icmp6, false},
				{udp4, false},
				{udp6, false},
				{tcp4Syn, false},
				{tcp4Synack, true},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, pc := range tc.expected {
				pd := pc.packetDef
				result := runClassicBpf(t, tc.program, pd.packet)
				// reject or accept
				if result != 0 && result != 262144 {
					require.Failf(t, "Unexpected BPF result", "packet: %s, result: %d", pd.name, result)
				}
				captured := result != 0
				assert.Equal(t, pc.shouldCapture, captured, "filter wrong for packet type %s", pd.name)
			}
		})
	}
}
