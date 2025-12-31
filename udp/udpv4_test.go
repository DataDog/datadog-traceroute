// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build test

package udp

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
)

func TestCreateRawUDPBuffer(t *testing.T) {
	srcIP := net.ParseIP("1.2.3.4")
	dstIP := net.ParseIP("5.6.7.8")
	srcPort := uint16(12345)
	dstPort := uint16(33434)
	ttl := 4

	udp := NewUDPv4(dstIP, dstPort, 1, 1, 0, 0, false)
	udp.srcIP = srcIP
	udp.srcPort = srcPort

	expectedIPHeader := &ipv4.Header{
		Version:  4,
		TTL:      ttl,
		ID:       41821 + ttl,
		Protocol: 17,
		Dst:      dstIP,
		Src:      srcIP,
		Len:      20,
		TotalLen: 36,
		Checksum: 50008,
		Flags:    2, // Don't fragment flag set
	}

	// most of this is just copied from the output of the function
	// we don't need to test gopacket's ability to serialize a packet
	// we need to ensure that the logic that calculates the payload is correct
	// which means we have to check the last 8 bytes of the packet, really just
	// the last two
	expectedPktBytes := []byte{0x45, 0x0, 0x0, 0x24, 0xa3, 0x61, 0x40, 0x0, 0x4, 0x11, 0xc3, 0x54, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x30, 0x39, 0x82, 0x9a, 0x0, 0x10, 0xba, 0xe3, 0x4e, 0x53, 0x4d, 0x4e, 0x43, 0x0, 0xa3, 0x61}

	// based on bytes 26-27 of expectedPktBytes
	expectedChecksum := uint16(0xbae3)

	ipHeaderID, pktBytes, actualChecksum, err := udp.createRawUDPBuffer(udp.srcIP, udp.srcPort, udp.Target, udp.TargetPort, uint8(ttl))

	require.NoError(t, err)
	assert.Equal(t, uint16(expectedIPHeader.ID), ipHeaderID)
	assert.Equal(t, expectedPktBytes, pktBytes)
	assert.Equal(t, expectedChecksum, actualChecksum)
}

func TestCreateRawUDPBufferIPv6(t *testing.T) {
	srcIP := net.ParseIP("2001:db8::1")
	dstIP := net.ParseIP("2001:db8::2")
	srcPort := uint16(12345)
	dstPort := uint16(33434)
	ttl := uint8(4)

	udp := NewUDPv4(dstIP, dstPort, 1, 30, 0, 0, false)
	udp.srcIP = srcIP
	udp.srcPort = srcPort

	// Generate the packet
	id, pktBytes, checksum, err := udp.createRawUDPBuffer(udp.srcIP, udp.srcPort, udp.Target, udp.TargetPort, ttl)
	require.NoError(t, err)

	// Verify packet structure by parsing it back
	packet := gopacket.NewPacket(pktBytes, layers.LayerTypeIPv6, gopacket.Default)

	// Check IPv6 layer
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	require.NotNil(t, ipv6Layer, "IPv6 layer should exist")
	ipv6 := ipv6Layer.(*layers.IPv6)

	assert.Equal(t, uint8(6), ipv6.Version, "should be IPv6")
	assert.Equal(t, ttl, ipv6.HopLimit, "hop limit should match TTL")
	assert.Equal(t, layers.IPProtocolUDP, ipv6.NextHeader, "next header should be UDP")
	assert.True(t, srcIP.Equal(ipv6.SrcIP), "source IP should match")
	assert.True(t, dstIP.Equal(ipv6.DstIP), "destination IP should match")

	// Check UDP layer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	require.NotNil(t, udpLayer, "UDP layer should exist")
	udpParsed := udpLayer.(*layers.UDP)

	assert.Equal(t, layers.UDPPort(srcPort), udpParsed.SrcPort, "source port should match")
	assert.Equal(t, layers.UDPPort(dstPort), udpParsed.DstPort, "destination port should match")
	assert.NotZero(t, checksum, "checksum should be computed")

	// For IPv6, the ID is the UDP length (payload + header)
	// Payload length = len(magic) + ttl = 5 + 4 = 9
	// UDP header = 8
	// Total = 17
	expectedPayloadLen := uint16(len(magic)) + uint16(ttl)
	expectedID := expectedPayloadLen + 8 // UDP header size
	assert.Equal(t, expectedID, id, "ID should be UDP length for IPv6")

	// Verify payload contains magic string repeated
	payload := udpParsed.Payload
	assert.Equal(t, int(expectedPayloadLen), len(payload), "payload length should match")
	assert.Equal(t, "NSMNCNSM", string(payload[:8]), "payload should start with repeated magic")
}

func TestCreateRawUDPBufferIPv6DifferentTTLs(t *testing.T) {
	srcIP := net.ParseIP("2001:db8::1")
	dstIP := net.ParseIP("2001:db8::2")
	srcPort := uint16(12345)
	dstPort := uint16(33434)

	udp := NewUDPv4(dstIP, dstPort, 1, 30, 0, 0, false)
	udp.srcIP = srcIP
	udp.srcPort = srcPort

	// Test different TTLs produce different packet IDs (which is UDP length for IPv6)
	ttls := []uint8{1, 5, 10, 30}
	ids := make(map[uint16]bool)

	for _, ttl := range ttls {
		id, pktBytes, _, err := udp.createRawUDPBuffer(udp.srcIP, udp.srcPort, udp.Target, udp.TargetPort, ttl)
		require.NoError(t, err)
		require.NotEmpty(t, pktBytes)

		// Each TTL should produce a unique ID (since payload length varies with TTL)
		assert.False(t, ids[id], "ID %d for TTL %d should be unique", id, ttl)
		ids[id] = true

		// Verify the packet parses correctly
		packet := gopacket.NewPacket(pktBytes, layers.LayerTypeIPv6, gopacket.Default)
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
		require.NotNil(t, ipv6Layer, "IPv6 layer should exist for TTL %d", ttl)
		ipv6 := ipv6Layer.(*layers.IPv6)
		assert.Equal(t, ttl, ipv6.HopLimit, "hop limit should match TTL %d", ttl)
	}
}
