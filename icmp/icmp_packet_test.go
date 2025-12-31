// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build test

package icmp

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-traceroute/packets"
)

func TestGeneratePacketV4(t *testing.T) {
	srcIP := netip.MustParseAddr("1.2.3.4")
	dstIP := netip.MustParseAddr("5.6.7.8")
	ttl := uint8(5)
	echoID := uint16(12345)

	gen := icmpPacketGen{
		ipPair: packets.IPPair{
			SrcAddr: srcIP,
			DstAddr: dstIP,
		},
	}

	pktBytes, err := gen.generate(ttl, echoID, false)
	require.NoError(t, err)
	require.NotEmpty(t, pktBytes)

	// Verify IPv4 header
	assert.Equal(t, uint8(0x45), pktBytes[0], "packet should start with IPv4 version and IHL")
	assert.Equal(t, ttl, pktBytes[8], "TTL should match")
	assert.Equal(t, uint8(1), pktBytes[9], "Protocol should be ICMP (1)")

	// Verify source and destination IPs
	assert.Equal(t, srcIP.AsSlice(), pktBytes[12:16], "Source IP should match")
	assert.Equal(t, dstIP.AsSlice(), pktBytes[16:20], "Destination IP should match")

	// Parse and verify the packet
	var ip4 layers.IPv4
	var icmpv4 layers.ICMPv4
	var payload gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &icmpv4, &payload)
	decoded := []gopacket.LayerType{}
	err = parser.DecodeLayers(pktBytes, &decoded)
	require.NoError(t, err)

	assert.Equal(t, uint8(layers.ICMPv4TypeEchoRequest), uint8(icmpv4.TypeCode.Type()))
	assert.Equal(t, echoID, icmpv4.Id)
	assert.Equal(t, uint16(ttl), icmpv4.Seq)
}

func TestGeneratePacketV6(t *testing.T) {
	srcIP := netip.MustParseAddr("2001:db8::1")
	dstIP := netip.MustParseAddr("2001:db8::2")
	ttl := uint8(5)
	echoID := uint16(12345)

	gen := icmpPacketGen{
		ipPair: packets.IPPair{
			SrcAddr: srcIP,
			DstAddr: dstIP,
		},
	}

	pktBytes, err := gen.generate(ttl, echoID, true)
	require.NoError(t, err)
	require.NotEmpty(t, pktBytes)

	// Verify IPv6 header
	assert.Equal(t, uint8(0x60), pktBytes[0]&0xf0, "packet should start with IPv6 version")
	assert.Equal(t, ttl, pktBytes[7], "HopLimit should match TTL")
	assert.Equal(t, uint8(58), pktBytes[6], "NextHeader should be ICMPv6 (58)")

	// Verify source and destination IPs (bytes 8-23 for src, 24-39 for dst)
	assert.Equal(t, srcIP.AsSlice(), pktBytes[8:24], "Source IP should match")
	assert.Equal(t, dstIP.AsSlice(), pktBytes[24:40], "Destination IP should match")

	// Parse and verify the packet - use IgnoreUnsupported to skip ICMPv6Echo layer
	var ip6 layers.IPv6
	var icmpv6 layers.ICMPv6
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ip6, &icmpv6)
	parser.IgnoreUnsupported = true
	decoded := []gopacket.LayerType{}
	err = parser.DecodeLayers(pktBytes, &decoded)
	require.NoError(t, err)

	assert.Equal(t, uint8(layers.ICMPv6TypeEchoRequest), uint8(icmpv6.TypeCode.Type()))

	// Verify ICMPv6 payload contains ID and Seq
	// ICMPv6 Echo Request payload format: [ID (2 bytes)][Seq (2 bytes)][data...]
	payload := icmpv6.Payload
	require.GreaterOrEqual(t, len(payload), 4)
	payloadID := binary.BigEndian.Uint16(payload[0:2])
	payloadSeq := binary.BigEndian.Uint16(payload[2:4])
	assert.Equal(t, echoID, payloadID, "Echo ID in payload should match")
	assert.Equal(t, uint16(ttl), payloadSeq, "Echo Seq in payload should match TTL")
}

func TestGeneratePacketV6DifferentTTLs(t *testing.T) {
	srcIP := netip.MustParseAddr("2001:db8::1")
	dstIP := netip.MustParseAddr("2001:db8::2")
	echoID := uint16(12345)

	gen := icmpPacketGen{
		ipPair: packets.IPPair{
			SrcAddr: srcIP,
			DstAddr: dstIP,
		},
	}

	ttls := []uint8{1, 5, 10, 30}

	for _, ttl := range ttls {
		pktBytes, err := gen.generate(ttl, echoID, true)
		require.NoError(t, err)
		require.NotEmpty(t, pktBytes)

		// Verify HopLimit in IPv6 header matches TTL
		assert.Equal(t, ttl, pktBytes[7], "HopLimit should match TTL=%d", ttl)

		// Parse and verify payload seq matches TTL
		var ip6 layers.IPv6
		var icmpv6 layers.ICMPv6
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ip6, &icmpv6)
		parser.IgnoreUnsupported = true
		decoded := []gopacket.LayerType{}
		err = parser.DecodeLayers(pktBytes, &decoded)
		require.NoError(t, err)

		payload := icmpv6.Payload
		require.GreaterOrEqual(t, len(payload), 4)
		payloadSeq := binary.BigEndian.Uint16(payload[2:4])
		assert.Equal(t, uint16(ttl), payloadSeq, "Echo Seq should match TTL=%d", ttl)
	}
}

func TestGeneratePacketV6Checksum(t *testing.T) {
	srcIP := netip.MustParseAddr("2001:db8::1")
	dstIP := netip.MustParseAddr("2001:db8::2")
	ttl := uint8(5)
	echoID := uint16(12345)

	gen := icmpPacketGen{
		ipPair: packets.IPPair{
			SrcAddr: srcIP,
			DstAddr: dstIP,
		},
	}

	pktBytes, err := gen.generate(ttl, echoID, true)
	require.NoError(t, err)

	// Parse the packet
	var ip6 layers.IPv6
	var icmpv6 layers.ICMPv6
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ip6, &icmpv6)
	parser.IgnoreUnsupported = true
	decoded := []gopacket.LayerType{}
	err = parser.DecodeLayers(pktBytes, &decoded)
	require.NoError(t, err)

	// ICMPv6 checksum should be non-zero (computed)
	assert.NotZero(t, icmpv6.Checksum, "ICMPv6 checksum should be computed")
}

func TestGeneratePacketV4DifferentTTLs(t *testing.T) {
	srcIP := netip.MustParseAddr("1.2.3.4")
	dstIP := netip.MustParseAddr("5.6.7.8")
	echoID := uint16(12345)

	gen := icmpPacketGen{
		ipPair: packets.IPPair{
			SrcAddr: srcIP,
			DstAddr: dstIP,
		},
	}

	ttls := []uint8{1, 5, 10, 30}

	for _, ttl := range ttls {
		pktBytes, err := gen.generate(ttl, echoID, false)
		require.NoError(t, err)
		require.NotEmpty(t, pktBytes)

		// Verify TTL in IPv4 header matches
		assert.Equal(t, ttl, pktBytes[8], "TTL should match %d", ttl)

		// Parse and verify ICMP Seq matches TTL
		var ip4 layers.IPv4
		var icmpv4 layers.ICMPv4
		var payload gopacket.Payload
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &icmpv4, &payload)
		decoded := []gopacket.LayerType{}
		err = parser.DecodeLayers(pktBytes, &decoded)
		require.NoError(t, err)

		assert.Equal(t, uint16(ttl), icmpv4.Seq, "ICMP Seq should match TTL=%d", ttl)
	}
}

func TestGeneratePacketV6LinklocalAddr(t *testing.T) {
	// Test with link-local IPv6 addresses
	srcIP := netip.MustParseAddr("fe80::1")
	dstIP := netip.MustParseAddr("fe80::2")
	ttl := uint8(1)
	echoID := uint16(99)

	gen := icmpPacketGen{
		ipPair: packets.IPPair{
			SrcAddr: srcIP,
			DstAddr: dstIP,
		},
	}

	pktBytes, err := gen.generate(ttl, echoID, true)
	require.NoError(t, err)
	require.NotEmpty(t, pktBytes)

	// Verify addresses
	assert.Equal(t, srcIP.AsSlice(), pktBytes[8:24], "Source IP should match")
	assert.Equal(t, dstIP.AsSlice(), pktBytes[24:40], "Destination IP should match")
}
