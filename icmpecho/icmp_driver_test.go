// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package icmpecho

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/packets"
)

func initTest(t *testing.T) (*ICMPv4, *icmpDriver, *packets.MockSink, *packets.MockSource) {
	packets.RandomizePacketIDBase()

	ctrl := gomock.NewController(t)
	mockSource := packets.NewMockSource(ctrl)
	mockSink := packets.NewMockSink(ctrl)

	config := NewICMPv4(
		net.ParseIP("1.2.3.4"),
		1,
		30,
		10*time.Millisecond,
		1*time.Second,
		false,
	)
	config.srcIP = net.ParseIP("5.6.7.8")
	config.identifier = 12345
	config.seqBase = 1000

	driver := newICMPDriver(config, mockSink, mockSource)

	return config, driver, mockSink, mockSource
}

func parseICMPEchoAndExpectFields(t *testing.T, config *ICMPv4, packetID uint16, ttl uint8, buf []byte) {
	parser := packets.NewFrameParser()
	err := parser.Parse(buf)
	require.NoError(t, err)

	require.Equal(t, layers.LayerTypeIPv4, parser.GetIPLayer())
	require.Equal(t, layers.LayerTypeICMPv4, parser.GetTransportLayer())

	require.Equal(t, uint8(layers.ICMPv4TypeEchoRequest), parser.ICMP4.TypeCode.Type())

	require.True(t, config.srcIP.Equal(parser.IP4.SrcIP))
	require.True(t, config.Target.Equal(parser.IP4.DstIP))

	require.Equal(t, packetID, parser.IP4.Id)
	require.Equal(t, ttl, parser.IP4.TTL)
	require.Equal(t, config.identifier, parser.ICMP4.Id)
}

func mockICMPEchoReply(t *testing.T, config *ICMPv4, seqNum uint16) []byte {
	ipLayer := &layers.IPv4{
		Version:  4,
		Length:   20,
		TTL:      42,
		Id:       1234,
		Protocol: layers.IPProtocolICMPv4,
		DstIP:    config.srcIP,
		SrcIP:    config.Target,
	}

	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		Id:       config.identifier,
		Seq:      seqNum,
	}

	payload := gopacket.Payload([]byte("DATADOG"))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buf, opts,
		ipLayer,
		icmpLayer,
		payload,
	)
	require.NoError(t, err)
	return buf.Bytes()
}

func mockICMPTTLExceeded(t *testing.T, config *ICMPv4, hopIP net.IP, ttl uint8, basePacketID uint16) []byte {
	ipLayer := &layers.IPv4{
		Version:  4,
		Length:   20,
		TTL:      42,
		Id:       1234,
		Protocol: layers.IPProtocolICMPv4,
		DstIP:    config.srcIP,
		SrcIP:    hopIP,
	}

	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeTimeExceeded, layers.ICMPv4CodeTTLExceeded),
	}

	// Inner IP packet that was being sent
	innerIPLayer := &layers.IPv4{
		Version:  4,
		Length:   20,
		TTL:      ttl,
		Id:       basePacketID + uint16(ttl),
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    config.srcIP,
		DstIP:    config.Target,
	}

	// Inner ICMP Echo Request header (first 8 bytes)
	seqNum := config.seqBase + uint16(ttl)
	innerICMPPayload := make([]byte, 8)
	innerICMPPayload[0] = byte(layers.ICMPv4TypeEchoRequest)
	innerICMPPayload[1] = 0 // code
	// checksum (2 bytes) - we don't need to compute it for matching
	innerICMPPayload[4] = byte(config.identifier >> 8)
	innerICMPPayload[5] = byte(config.identifier & 0xff)
	innerICMPPayload[6] = byte(seqNum >> 8)
	innerICMPPayload[7] = byte(seqNum & 0xff)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buf, opts,
		ipLayer,
		icmpLayer,
		innerIPLayer,
		gopacket.Payload(innerICMPPayload),
	)
	require.NoError(t, err)
	return buf.Bytes()
}

func mockRead(mockSource *packets.MockSource, packet []byte) {
	mockSource.EXPECT().Read(gomock.Any()).DoAndReturn(func(buf []byte) (int, error) {
		n := copy(buf, packet)
		return n, nil
	})
}

func TestICMPDriverSupportsParallel(t *testing.T) {
	_, driver, _, _ := initTest(t)

	info := driver.GetDriverInfo()
	require.Equal(t, common.TracerouteDriverInfo{
		SupportsParallel: true,
	}, info)
}

func TestICMPDriverTwoHops(t *testing.T) {
	config, driver, mockSink, mockSource := initTest(t)

	// *** TTL=1 -- get back an ICMP TTL exceeded
	mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).DoAndReturn(func(buf []byte, addrPort netip.AddrPort) error {
		parseICMPEchoAndExpectFields(t, config, driver.basePacketID+1, 1, buf)
		require.True(t, config.Target.Equal(addrPort.Addr().AsSlice()))
		require.Equal(t, uint16(0), addrPort.Port()) // ICMP uses port 0
		return nil
	})

	// trigger the mock
	err := driver.SendProbe(1)
	require.NoError(t, err)

	// make the source return an ICMP TTL exceeded
	hopIP := net.ParseIP("42.42.42.42")
	icmpResp := mockICMPTTLExceeded(t, config, hopIP, 1, driver.basePacketID)

	mockSource.EXPECT().SetReadDeadline(gomock.Any()).DoAndReturn(func(deadline time.Time) error {
		require.True(t, deadline.After(time.Now().Add(500*time.Millisecond)))
		return nil
	})
	mockRead(mockSource, icmpResp)

	// should get back the ICMP hop IP
	probeResp, err := driver.ReceiveProbe(1 * time.Second)
	require.NoError(t, err)
	require.Equal(t, uint8(1), probeResp.TTL)
	require.True(t, hopIP.Equal(probeResp.IP.AsSlice()))
	require.False(t, probeResp.IsDest)

	// *** TTL=2 -- get back an Echo Reply from destination
	mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).DoAndReturn(func(buf []byte, addrPort netip.AddrPort) error {
		parseICMPEchoAndExpectFields(t, config, driver.basePacketID+2, 2, buf)
		require.True(t, config.Target.Equal(addrPort.Addr().AsSlice()))
		return nil
	})

	// send the second packet
	err = driver.SendProbe(2)
	require.NoError(t, err)

	// return Echo Reply
	mockSource.EXPECT().SetReadDeadline(gomock.Any()).Return(nil)
	seqNum := config.seqBase + 2
	echoReply := mockICMPEchoReply(t, config, seqNum)
	mockRead(mockSource, echoReply)

	probeResp, err = driver.ReceiveProbe(1 * time.Second)
	require.NoError(t, err)
	require.Equal(t, uint8(2), probeResp.TTL)
	require.True(t, config.Target.Equal(probeResp.IP.AsSlice()))
	require.True(t, probeResp.IsDest)
}

func TestICMPDriverMismatchedIdentifier(t *testing.T) {
	config, driver, mockSink, mockSource := initTest(t)
	mockSource.EXPECT().SetReadDeadline(gomock.Any()).AnyTimes().Return(nil)
	mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(nil)

	// trigger the mock
	err := driver.SendProbe(1)
	require.NoError(t, err)

	// *** get back an Echo Reply with wrong identifier
	badConfig := *config
	badConfig.identifier = 54321 // wrong identifier
	seqNum := config.seqBase + 1
	echoReply := mockICMPEchoReply(t, &badConfig, seqNum)
	mockRead(mockSource, echoReply)

	probeResp, err := driver.ReceiveProbe(1 * time.Second)
	require.Nil(t, probeResp)
	require.ErrorIs(t, err, common.ErrPacketDidNotMatchTraceroute)
}

func TestICMPDriverMismatchedSeqNum(t *testing.T) {
	config, driver, mockSink, mockSource := initTest(t)
	mockSource.EXPECT().SetReadDeadline(gomock.Any()).AnyTimes().Return(nil)
	mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(nil)

	// trigger the mock
	err := driver.SendProbe(1)
	require.NoError(t, err)

	// *** get back an Echo Reply with wrong sequence number
	seqNum := config.seqBase + 99 // wrong sequence number
	echoReply := mockICMPEchoReply(t, config, seqNum)
	mockRead(mockSource, echoReply)

	probeResp, err := driver.ReceiveProbe(1 * time.Second)
	require.Nil(t, probeResp)
	require.ErrorIs(t, err, common.ErrPacketDidNotMatchTraceroute)
}

func TestICMPDriverTTLExceededMismatchedIP(t *testing.T) {
	config, driver, mockSink, mockSource := initTest(t)
	mockSource.EXPECT().SetReadDeadline(gomock.Any()).AnyTimes().Return(nil)
	mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(nil)

	// trigger the mock
	err := driver.SendProbe(1)
	require.NoError(t, err)

	// *** get back a TTL exceeded with wrong source IP in embedded packet
	hopIP := net.ParseIP("42.42.42.42")
	badConfig := *config
	badConfig.srcIP = net.ParseIP("8.8.8.8") // wrong source IP
	icmpResp := mockICMPTTLExceeded(t, &badConfig, hopIP, 1, driver.basePacketID)

	mockRead(mockSource, icmpResp)

	probeResp, err := driver.ReceiveProbe(1 * time.Second)
	require.Nil(t, probeResp)
	require.ErrorIs(t, err, common.ErrPacketDidNotMatchTraceroute)
}

func TestParseICMPEchoFirstBytes(t *testing.T) {
	// Test valid payload - full ICMP header: Type(1) + Code(1) + Checksum(2) + ID(2) + Seq(2)
	payload := []byte{
		0x08, 0x00, // Type=8 (Echo Request), Code=0
		0x00, 0x00, // Checksum (placeholder)
		0x12, 0x34, // ID
		0x56, 0x78, // Seq
	}
	info, err := parseICMPEchoFirstBytes(payload)
	require.NoError(t, err)
	require.Equal(t, uint16(0x1234), info.ID)
	require.Equal(t, uint16(0x5678), info.Seq)

	// Test payload too short
	shortPayload := []byte{0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56}
	_, err = parseICMPEchoFirstBytes(shortPayload)
	require.Error(t, err)
}
