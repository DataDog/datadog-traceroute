// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package packets

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

// buildTCPPacket returns a minimal serialized IPv4/TCP packet usable as Source.Read output.
func buildTCPPacket(t *testing.T) []byte {
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
		ACK:     true,
		Seq:     1234,
		Ack:     5678,
		Window:  1024,
	}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip4))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, ip4, tcp, gopacket.Payload([]byte{1})))
	return buf.Bytes()
}

// delayedTimestampedSource simulates a capture backend that buffers/delays delivery
// of a packet to userspace while still reporting the original kernel capture time.
type delayedTimestampedSource struct {
	packet    []byte
	kernelTS  time.Time
	sleepTime time.Duration
}

func (d *delayedTimestampedSource) Read(buf []byte) (int, error) {
	time.Sleep(d.sleepTime)
	return copy(buf, d.packet), nil
}

func (d *delayedTimestampedSource) Close() error                             { return nil }
func (d *delayedTimestampedSource) SetReadDeadline(_ time.Time) error        { return nil }
func (d *delayedTimestampedSource) SetPacketFilter(_ PacketFilterSpec) error { return nil }
func (d *delayedTimestampedSource) LastPacketTimestamp() (time.Time, bool) {
	return d.kernelTS, true
}

var _ Source = &delayedTimestampedSource{}
var _ TimestampedSource = &delayedTimestampedSource{}

func TestReadAndParseUsesKernelTimestampOverDelayedDelivery(t *testing.T) {
	kernelTS := time.Now().Add(-500 * time.Millisecond)
	source := &delayedTimestampedSource{
		packet:    buildTCPPacket(t),
		kernelTS:  kernelTS,
		sleepTime: 50 * time.Millisecond,
	}

	parser := NewFrameParser()
	receivedAt, err := ReadAndParse(source, make([]byte, 4096), parser)
	require.NoError(t, err)

	require.True(t, receivedAt.Equal(kernelTS), "expected the kernel capture timestamp, not delivery time")
	require.Less(t, time.Since(receivedAt), 600*time.Millisecond)
	require.Greater(t, time.Since(receivedAt), 400*time.Millisecond)
}

// plainSource has no timestamp capability, so ReadAndParse must fall back to time.Now().
type plainSource struct {
	packet []byte
}

func (p *plainSource) Read(buf []byte) (int, error)             { return copy(buf, p.packet), nil }
func (p *plainSource) Close() error                             { return nil }
func (p *plainSource) SetReadDeadline(_ time.Time) error        { return nil }
func (p *plainSource) SetPacketFilter(_ PacketFilterSpec) error { return nil }

var _ Source = &plainSource{}

func TestReadAndParseFallsBackToNowWithoutKernelTimestamp(t *testing.T) {
	source := &plainSource{packet: buildTCPPacket(t)}

	parser := NewFrameParser()
	before := time.Now()
	receivedAt, err := ReadAndParse(source, make([]byte, 4096), parser)
	after := time.Now()
	require.NoError(t, err)

	require.False(t, receivedAt.Before(before))
	require.False(t, receivedAt.After(after))
}

func TestRTTFallsBackToNowOnClockStepBackward(t *testing.T) {
	sendTime := time.Now()
	// simulate a kernel capture timestamp that predates sendTime, e.g. because the
	// system wall clock stepped backward between the two readings.
	receivedAt := sendTime.Add(-time.Second)

	rtt := RTT(receivedAt, sendTime)
	require.GreaterOrEqual(t, rtt, time.Duration(0), "RTT must never be negative")
}

func TestRTTUsesCaptureTimestampWhenNonNegative(t *testing.T) {
	sendTime := time.Now()
	receivedAt := sendTime.Add(10 * time.Millisecond)

	rtt := RTT(receivedAt, sendTime)
	require.Equal(t, 10*time.Millisecond, rtt)
}
