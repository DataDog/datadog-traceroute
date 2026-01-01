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

func initTest(t *testing.T, ipv6 bool) (*ICMPv4, *icmpDriver, *packets.MockSink, *packets.MockSource) {
	packets.RandomizePacketIDBase()

	ctrl := gomock.NewController(t)
	mockSource := packets.NewMockSource(ctrl)
	mockSink := packets.NewMockSink(ctrl)

	ipAddress := net.ParseIP("1.2.3.4")
	if ipv6 {
		ipAddress = net.ParseIP("2001:0db8:abcd:0012::0a00:fffe")
	}
	config := NewICMPv4(
		ipAddress,
		1,
		30,
		10*time.Millisecond,
		100*time.Second,
		false,
	)
	config.srcIP = net.ParseIP("5.6.7.8")
	if ipv6 {
		config.srcIP = net.ParseIP("2001:0db8:1234:5678:0000:0000:9abc:def0")
	}
	config.icmpID = 12345

	driver := newICMPDriver(config, mockSink, mockSource)

	return config, driver, mockSink, mockSource
}

func expectICMPIDs(t *testing.T, config *ICMPv4, buf []byte, ipv6 bool) {
	var IP4 layers.IPv4
	var IP6 layers.IPv6
	var ICMP4 layers.ICMPv4
	var ICMP6 layers.ICMPv6
	var Payload gopacket.Payload

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeIPv4,
		&IP4, &ICMP4, &Payload,
	)
	if ipv6 {
		parser = gopacket.NewDecodingLayerParser(
			layers.LayerTypeIPv6,
			&IP6, &ICMP6, &Payload,
		)
		// Ignore unsupported ICMPv6 layers since gopacket doesn't decode all ICMPv6 types fully
		parser.IgnoreUnsupported = true
	}
	decoded := []gopacket.LayerType{}
	err := parser.DecodeLayers(buf, &decoded)
	require.NoError(t, err)

	if ipv6 {
		require.True(t, config.srcIP.Equal(IP6.SrcIP))
		require.True(t, config.Target.Equal(IP6.DstIP))
		// For ICMPv6, verify the Echo Request type code
		require.Equal(t, layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0), ICMP6.TypeCode)
	} else {
		require.True(t, config.srcIP.Equal(IP4.SrcIP))
		require.True(t, config.Target.Equal(IP4.DstIP))
		require.Equal(t, config.icmpID, ICMP4.Id)
	}
}

func mockICMPTTLExceeded(t *testing.T, config *ICMPv4, hopIP net.IP, ttl uint8) []byte {
	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		DstIP:    config.srcIP,
		SrcIP:    hopIP,
	}

	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeTimeExceeded, layers.ICMPv4CodeTTLExceeded),
	}

	innerIPLayer := &layers.IPv4{
		Version:  4,
		TTL:      ttl,
		Id:       41821 + uint16(ttl),
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    config.srcIP,
		DstIP:    config.Target,
	}

	// Inner ICMP Echo Request: type(1) + code(1) + checksum(2) + id(2) + seq(2)
	innerICMP := make([]byte, 8)
	innerICMP[0] = 8 // Echo Request type
	innerICMP[1] = 0 // Code
	// checksum at [2:4] - leaving as 0 for test
	innerICMP[4] = byte((config.icmpID >> 8) & 0xff)
	innerICMP[5] = byte(config.icmpID & 0xff)
	seqNum := uint16(ttl)
	innerICMP[6] = byte((seqNum >> 8) & 0xff)
	innerICMP[7] = byte(seqNum & 0xff)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buf, opts,
		ipLayer,
		icmpLayer,
		innerIPLayer,
		gopacket.Payload(innerICMP),
	)
	require.NoError(t, err)
	return buf.Bytes()
}

func mockICMPEchoReply(t *testing.T, config *ICMPv4, ttl uint8) []byte {
	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		DstIP:    config.srcIP,
		SrcIP:    config.Target,
	}

	seqNum := uint16(ttl)
	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		Id:       config.icmpID,
		Seq:      seqNum,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buf, opts,
		ipLayer,
		icmpLayer,
	)
	require.NoError(t, err)
	return buf.Bytes()
}

func mockICMPTTLExceededIPv6(t *testing.T, config *ICMPv4, hopIP net.IP, ttl uint8) []byte {
	ipLayer := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   64,
		SrcIP:      hopIP,
		DstIP:      config.srcIP,
	}

	icmpLayer := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeTimeExceeded, 0),
	}
	err := icmpLayer.SetNetworkLayerForChecksum(ipLayer)
	require.NoError(t, err)

	innerIPLayer := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   64,
		SrcIP:      config.srcIP,
		DstIP:      config.Target,
	}

	// Inner ICMPv6 Echo Request: type(1) + code(1) + checksum(2) + id(2) + seq(2)
	innerICMP := make([]byte, 8)
	innerICMP[0] = 128 // Echo Request type
	innerICMP[1] = 0   // Code
	// checksum at [2:4] - leaving as 0 for test
	innerICMP[4] = byte((config.icmpID >> 8) & 0xff)
	innerICMP[5] = byte(config.icmpID & 0xff)
	seqNum := uint16(ttl)
	innerICMP[6] = byte((seqNum >> 8) & 0xff)
	innerICMP[7] = byte(seqNum & 0xff)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err = gopacket.SerializeLayers(buf, opts,
		ipLayer,
		icmpLayer,
		// 4 unused bytes before the embedded packet in ICMPv6 Time Exceeded
		gopacket.Payload([]byte{0, 0, 0, 0}),
		innerIPLayer,
		gopacket.Payload(innerICMP),
	)
	require.NoError(t, err)
	return buf.Bytes()
}

func mockICMPEchoReplyIPv6(t *testing.T, config *ICMPv4, ttl uint8) []byte {
	ipLayer := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   64,
		SrcIP:      config.Target,
		DstIP:      config.srcIP,
	}

	icmpLayer := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoReply, 0),
	}
	err := icmpLayer.SetNetworkLayerForChecksum(ipLayer)
	require.NoError(t, err)

	// ICMPv6 Echo Reply payload: id(2) + seq(2)
	seqNum := uint16(ttl)
	payload := make([]byte, 4)
	payload[0] = byte((config.icmpID >> 8) & 0xff)
	payload[1] = byte(config.icmpID & 0xff)
	payload[2] = byte((seqNum >> 8) & 0xff)
	payload[3] = byte(seqNum & 0xff)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err = gopacket.SerializeLayers(buf, opts,
		ipLayer,
		icmpLayer,
		gopacket.Payload(payload),
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

func TestICMPDriverTwoHops(t *testing.T) {
	config, driver, mockSink, mockSource := initTest(t, false)

	// *** TTL=1 -- get back an ICMP TTL exceeded
	mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).DoAndReturn(func(buf []byte, addrPort netip.AddrPort) error {
		expectICMPIDs(t, config, buf, false)
		require.True(t, config.Target.Equal(addrPort.Addr().AsSlice()))
		require.Equal(t, uint16(0), addrPort.Port()) // ICMP has no port
		return nil
	})

	// trigger the mock
	err := driver.SendProbe(1)
	require.NoError(t, err)

	// make the source return an ICMP TTL exceeded
	hopIP := net.ParseIP("42.42.42.42")
	icmpResp := mockICMPTTLExceeded(t, config, hopIP, 1)

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

	mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).DoAndReturn(func(buf []byte, addrPort netip.AddrPort) error {
		expectICMPIDs(t, config, buf, false)
		require.True(t, config.Target.Equal(addrPort.Addr().AsSlice()))
		return nil
	})

	// send the second packet
	err = driver.SendProbe(2)
	require.NoError(t, err)

	mockSource.EXPECT().SetReadDeadline(gomock.Any()).Return(nil)
	icmpResp = mockICMPEchoReply(t, config, 2)
	mockRead(mockSource, icmpResp)

	probeResp, err = driver.ReceiveProbe(1 * time.Second)
	require.NoError(t, err)
	require.Equal(t, uint8(2), probeResp.TTL)
	require.True(t, config.Target.Equal(probeResp.IP.AsSlice()))
	require.True(t, probeResp.IsDest)
}

func TestICMPDriverTwoHopsIPv6(t *testing.T) {
	config, driver, mockSink, mockSource := initTest(t, true)

	// *** TTL=1 -- get back an ICMP TTL exceeded
	mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).DoAndReturn(func(buf []byte, addrPort netip.AddrPort) error {
		expectICMPIDs(t, config, buf, true)
		require.True(t, config.Target.Equal(addrPort.Addr().AsSlice()))
		return nil
	})

	// trigger the mock
	err := driver.SendProbe(1)
	require.NoError(t, err)

	// make the source return an ICMP TTL exceeded
	hopIP := net.ParseIP("2001:0db8:85a3::8a2e:0370:7334")
	icmpResp := mockICMPTTLExceededIPv6(t, config, hopIP, 1)

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

	mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).DoAndReturn(func(buf []byte, addrPort netip.AddrPort) error {
		expectICMPIDs(t, config, buf, true)
		require.True(t, config.Target.Equal(addrPort.Addr().AsSlice()))
		return nil
	})

	// send the second packet
	err = driver.SendProbe(2)
	require.NoError(t, err)

	mockSource.EXPECT().SetReadDeadline(gomock.Any()).Return(nil)
	icmpResp = mockICMPEchoReplyIPv6(t, config, 2)
	mockRead(mockSource, icmpResp)

	probeResp, err = driver.ReceiveProbe(1 * time.Second)
	require.NoError(t, err)
	require.Equal(t, uint8(2), probeResp.TTL)
	require.True(t, config.Target.Equal(probeResp.IP.AsSlice()))
	require.True(t, probeResp.IsDest)
}

func TestICMPDriverMismatchedID(t *testing.T) {
	config, driver, mockSink, mockSource := initTest(t, false)
	mockSource.EXPECT().SetReadDeadline(gomock.Any()).AnyTimes().Return(nil)
	mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(nil)

	// trigger the mock
	err := driver.SendProbe(1)
	require.NoError(t, err)

	// Create an ICMP TTL exceeded with a different ICMP ID
	badConfig := *config
	badConfig.icmpID = config.icmpID + 1

	hopIP := net.ParseIP("42.42.42.42")
	icmpResp := mockICMPTTLExceeded(t, &badConfig, hopIP, 1)
	mockRead(mockSource, icmpResp)

	probeResp, err := driver.ReceiveProbe(1 * time.Second)
	require.Nil(t, probeResp)
	require.ErrorIs(t, err, common.ErrPacketDidNotMatchTraceroute)
}

func TestICMPDriverMismatchedDestination(t *testing.T) {
	config, driver, mockSink, mockSource := initTest(t, false)
	mockSource.EXPECT().SetReadDeadline(gomock.Any()).AnyTimes().Return(nil)
	mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(nil)

	// trigger the mock
	err := driver.SendProbe(1)
	require.NoError(t, err)

	// Create an ICMP TTL exceeded with a different destination
	badConfig := *config
	badConfig.Target = net.ParseIP("8.8.8.8")

	hopIP := net.ParseIP("42.42.42.42")
	icmpResp := mockICMPTTLExceeded(t, &badConfig, hopIP, 1)
	mockRead(mockSource, icmpResp)

	probeResp, err := driver.ReceiveProbe(1 * time.Second)
	require.Nil(t, probeResp)
	require.ErrorIs(t, err, common.ErrPacketDidNotMatchTraceroute)
}

func TestICMPDriverEchoReplyMismatchedID(t *testing.T) {
	config, driver, mockSink, mockSource := initTest(t, false)
	mockSource.EXPECT().SetReadDeadline(gomock.Any()).AnyTimes().Return(nil)
	mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(nil)

	// trigger the mock
	err := driver.SendProbe(1)
	require.NoError(t, err)

	// Create an Echo Reply with a different ICMP ID
	badConfig := *config
	badConfig.icmpID = config.icmpID + 1

	icmpResp := mockICMPEchoReply(t, &badConfig, 1)
	mockRead(mockSource, icmpResp)

	probeResp, err := driver.ReceiveProbe(1 * time.Second)
	require.Nil(t, probeResp)
	require.ErrorIs(t, err, common.ErrPacketDidNotMatchTraceroute)
}

func TestParseInnerICMPEchoRequest(t *testing.T) {
	t.Run("ICMPv4", func(t *testing.T) {
		// Valid Echo Request
		payload := []byte{8, 0, 0, 0, 0x30, 0x39, 0x00, 0x05} // type=8, code=0, checksum=0, id=12345, seq=5
		info, err := parseInnerICMPEchoRequest(payload, icmpv4EchoRequestType)
		require.NoError(t, err)
		require.Equal(t, uint16(12345), info.ID)
		require.Equal(t, uint16(5), info.Seq)

		// Payload too short
		_, err = parseInnerICMPEchoRequest([]byte{8, 0, 0, 0}, icmpv4EchoRequestType)
		require.Error(t, err)

		// Wrong type (not Echo Request)
		_, err = parseInnerICMPEchoRequest([]byte{0, 0, 0, 0, 0, 0, 0, 0}, icmpv4EchoRequestType) // type=0 (Echo Reply)
		require.Error(t, err)
	})

	t.Run("ICMPv6", func(t *testing.T) {
		// Valid Echo Request
		payload := []byte{128, 0, 0, 0, 0x30, 0x39, 0x00, 0x05} // type=128, code=0, checksum=0, id=12345, seq=5
		info, err := parseInnerICMPEchoRequest(payload, icmpv6EchoRequestType)
		require.NoError(t, err)
		require.Equal(t, uint16(12345), info.ID)
		require.Equal(t, uint16(5), info.Seq)

		// Payload too short
		_, err = parseInnerICMPEchoRequest([]byte{128, 0, 0, 0}, icmpv6EchoRequestType)
		require.Error(t, err)

		// Wrong type (not Echo Request)
		_, err = parseInnerICMPEchoRequest([]byte{129, 0, 0, 0, 0, 0, 0, 0}, icmpv6EchoRequestType) // type=129 (Echo Reply)
		require.Error(t, err)
	})
}
