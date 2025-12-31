// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build test

package udp

import (
	"net"
	"testing"

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

	udp := NewUDPv4(dstIP, dstPort, 1, 1, 0, 0, false)
	udp.srcIP = srcIP
	udp.srcPort = srcPort

	// For IPv6, the packet ID is the UDP payload length + 8 (UDP header)
	// UDP payload for IPv6 is: len("NSMNC") + TTL = 5 + 4 = 9 bytes
	// So packet ID = 9 + 8 = 17
	expectedPacketID := uint16(len(magic)) + uint16(ttl) + 8

	packetID, pktBytes, checksum, err := udp.createRawUDPBuffer(udp.srcIP, udp.srcPort, udp.Target, udp.TargetPort, ttl)

	require.NoError(t, err)
	assert.Equal(t, expectedPacketID, packetID)
	assert.NotEmpty(t, pktBytes)
	assert.NotZero(t, checksum)

	// Verify the packet starts with IPv6 version (0x60)
	assert.Equal(t, uint8(0x60), pktBytes[0]&0xf0, "packet should start with IPv6 version")

	// Verify HopLimit is set correctly (byte 7 in IPv6 header)
	assert.Equal(t, ttl, pktBytes[7], "HopLimit should match TTL")

	// Verify NextHeader is UDP (17) - byte 6 in IPv6 header
	assert.Equal(t, uint8(17), pktBytes[6], "NextHeader should be UDP (17)")
}

func TestCreateRawUDPBufferIPv6DifferentTTLs(t *testing.T) {
	srcIP := net.ParseIP("2001:db8::1")
	dstIP := net.ParseIP("2001:db8::2")
	srcPort := uint16(12345)
	dstPort := uint16(33434)

	udp := NewUDPv4(dstIP, dstPort, 1, 30, 0, 0, false)
	udp.srcIP = srcIP
	udp.srcPort = srcPort

	// Test that different TTLs produce different packet IDs and HopLimits
	ttls := []uint8{1, 5, 10, 30}
	prevPacketID := uint16(0)
	prevChecksum := uint16(0)

	for _, ttl := range ttls {
		packetID, pktBytes, checksum, err := udp.createRawUDPBuffer(udp.srcIP, udp.srcPort, udp.Target, udp.TargetPort, ttl)
		require.NoError(t, err)

		// Verify HopLimit in IPv6 header matches TTL
		assert.Equal(t, ttl, pktBytes[7], "HopLimit should match TTL=%d", ttl)

		// Expected packet ID for IPv6: len("NSMNC") + TTL + UDP header (8)
		expectedPacketID := uint16(len(magic)) + uint16(ttl) + 8
		assert.Equal(t, expectedPacketID, packetID, "packetID should be %d for TTL=%d", expectedPacketID, ttl)

		// Verify different TTLs produce different packet IDs
		if prevPacketID != 0 {
			assert.NotEqual(t, prevPacketID, packetID, "different TTLs should produce different packet IDs")
		}

		// Verify checksum is computed (different TTLs may produce different checksums)
		assert.NotZero(t, checksum)
		if prevChecksum != 0 {
			assert.NotEqual(t, prevChecksum, checksum, "different TTLs should produce different checksums")
		}

		prevPacketID = packetID
		prevChecksum = checksum
	}
}
