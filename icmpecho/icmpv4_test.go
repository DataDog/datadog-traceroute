// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package icmpecho

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-traceroute/packets"
)

func TestNewICMPv4(t *testing.T) {
	target := net.ParseIP("1.2.3.4")
	cfg := NewICMPv4(target, 1, 30, 50*time.Millisecond, 3*time.Second, false)

	require.NotNil(t, cfg)
	require.True(t, target.Equal(cfg.Target))
	require.Equal(t, uint8(1), cfg.MinTTL)
	require.Equal(t, uint8(30), cfg.MaxTTL)
	require.Equal(t, 50*time.Millisecond, cfg.Delay)
	require.Equal(t, 3*time.Second, cfg.Timeout)
	require.False(t, cfg.UseWindowsDriver)
}

func TestICMPv4Close(t *testing.T) {
	cfg := NewICMPv4(net.ParseIP("1.2.3.4"), 1, 30, 50*time.Millisecond, 3*time.Second, false)
	err := cfg.Close()
	require.NoError(t, err)
}

func TestCreateRawICMPEchoBuffer(t *testing.T) {
	target := net.ParseIP("1.2.3.4")
	srcIP := net.ParseIP("5.6.7.8")

	cfg := NewICMPv4(target, 1, 30, 50*time.Millisecond, 3*time.Second, false)
	cfg.srcIP = srcIP
	cfg.identifier = 12345
	cfg.seqBase = 1000

	packetID := uint16(41821)
	ttl := 5

	buf, err := cfg.createRawICMPEchoBuffer(packetID, ttl)
	require.NoError(t, err)
	require.NotEmpty(t, buf)

	// Parse the buffer and verify
	parser := packets.NewFrameParser()
	err = parser.Parse(buf)
	require.NoError(t, err)

	// Verify IP layer
	require.Equal(t, layers.LayerTypeIPv4, parser.GetIPLayer())
	require.True(t, srcIP.Equal(parser.IP4.SrcIP))
	require.True(t, target.Equal(parser.IP4.DstIP))
	require.Equal(t, uint8(ttl), parser.IP4.TTL)
	require.Equal(t, packetID, parser.IP4.Id)
	require.Equal(t, layers.IPProtocolICMPv4, parser.IP4.Protocol)

	// Verify ICMP layer
	require.Equal(t, layers.LayerTypeICMPv4, parser.GetTransportLayer())
	require.Equal(t, uint8(layers.ICMPv4TypeEchoRequest), parser.ICMP4.TypeCode.Type())
	require.Equal(t, cfg.identifier, parser.ICMP4.Id)
	require.Equal(t, cfg.seqBase+uint16(ttl), parser.ICMP4.Seq)
}

func TestCreateRawICMPEchoBufferDifferentTTLs(t *testing.T) {
	target := net.ParseIP("1.2.3.4")
	srcIP := net.ParseIP("5.6.7.8")

	cfg := NewICMPv4(target, 1, 30, 50*time.Millisecond, 3*time.Second, false)
	cfg.srcIP = srcIP
	cfg.identifier = 12345
	cfg.seqBase = 1000

	// Create packets with different TTLs and verify sequence numbers differ
	for ttl := 1; ttl <= 5; ttl++ {
		buf, err := cfg.createRawICMPEchoBuffer(uint16(41821+ttl), ttl)
		require.NoError(t, err)

		parser := packets.NewFrameParser()
		err = parser.Parse(buf)
		require.NoError(t, err)

		require.Equal(t, uint8(ttl), parser.IP4.TTL)
		require.Equal(t, cfg.seqBase+uint16(ttl), parser.ICMP4.Seq)
	}
}
