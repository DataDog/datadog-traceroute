// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package tcp

import (
	"context"
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
	"github.com/DataDog/datadog-traceroute/result"
)

func initTest(t *testing.T) (*TCPv4, *tcpDriver, *packets.MockSink, *packets.MockSource) {
	packets.RandomizePacketIDBase()

	ctrl := gomock.NewController(t)
	mockSource := packets.NewMockSource(ctrl)
	mockSink := packets.NewMockSink(ctrl)

	config := NewTCPv4(
		net.ParseIP("1.2.3.4"),
		80,
		1,
		30,
		10*time.Millisecond,
		1*time.Second,
		false,
		false,
	)
	config.srcIP = net.ParseIP("5.6.7.8")
	config.srcPort = 12345

	driver := newTCPDriver(config, mockSink, mockSource)

	return config, driver, mockSink, mockSource
}

func parseSynAndExpectIDs(t *testing.T, config *TCPv4, packetID uint16, seqNum uint32, buf []byte) {
	parser := packets.NewFrameParser()
	err := parser.Parse(buf)
	require.NoError(t, err)

	require.Equal(t, layers.LayerTypeIPv4, parser.GetIPLayer())
	require.Equal(t, layers.LayerTypeTCP, parser.GetTransportLayer())

	require.True(t, parser.TCP.SYN)
	require.False(t, parser.TCP.ACK)
	require.False(t, parser.TCP.RST)

	require.True(t, config.srcIP.Equal(parser.IP4.SrcIP))
	require.True(t, config.Target.Equal(parser.IP4.DstIP))

	require.Equal(t, config.srcPort, uint16(parser.TCP.SrcPort))
	require.Equal(t, config.DestPort, uint16(parser.TCP.DstPort))

	require.Equal(t, packetID, parser.IP4.Id)
	require.Equal(t, seqNum, parser.TCP.Seq)
}

func mockICMPResp(t *testing.T, config *TCPv4, hopIP net.IP, basePacketID uint16, ttl uint8, tcpInfo packets.TCPInfo) []byte {
	return mockICMPRespWithTypeCode(t, config, hopIP, basePacketID, ttl, tcpInfo,
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeTimeExceeded, layers.ICMPv4CodeTTLExceeded))
}

func mockICMPRespWithTypeCode(t *testing.T, config *TCPv4, hopIP net.IP, basePacketID uint16, ttl uint8, tcpInfo packets.TCPInfo, typeCode layers.ICMPv4TypeCode) []byte {
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
		TypeCode: typeCode,
	}
	innerIPLayer := &layers.IPv4{
		Version:  4,
		Length:   20,
		TTL:      ttl,
		Id:       basePacketID + uint16(ttl),
		Protocol: layers.IPProtocolTCP,
		SrcIP:    config.srcIP,
		DstIP:    config.Target,
	}

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	innerTCP := &layers.TCP{
		SrcPort: layers.TCPPort(tcpInfo.SrcPort),
		DstPort: layers.TCPPort(tcpInfo.DstPort),
		Seq:     tcpInfo.Seq,
		SYN:     true,
	}
	require.NoError(t, innerTCP.SetNetworkLayerForChecksum(innerIPLayer))
	innerBuf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(innerBuf, opts, innerIPLayer, innerTCP))
	// RFC 792 quotes the original IP header (including its full packet length)
	// and only the first 8 transport bytes.
	payload := innerBuf.Bytes()[:28]

	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, opts,
		ipLayer,
		icmpLayer,
		gopacket.Payload(payload),
	)
	require.NoError(t, err)
	return buf.Bytes()
}

func mockTCPResp(t *testing.T, config *TCPv4, syn, ack, rst bool, seqNum uint32) []byte {
	ipLayer := &layers.IPv4{
		Version:  4,
		Length:   20,
		TTL:      42,
		Id:       1234,
		Protocol: layers.IPProtocolTCP,
		DstIP:    config.srcIP,
		SrcIP:    config.Target,
	}

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(config.DestPort),
		DstPort: layers.TCPPort(config.srcPort),
		Seq:     123,
		Ack:     seqNum + 1,
		SYN:     syn,
		ACK:     ack,
		RST:     rst,
		Window:  1024,
	}

	err := tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	require.NoError(t, err)

	// clear the gopacket.SerializeBuffer
	buf := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err = gopacket.SerializeLayers(buf, opts,
		ipLayer,
		tcpLayer,
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

func TestTCPDriverNoParallel(t *testing.T) {
	_, driver, _, _ := initTest(t)

	info := driver.GetDriverInfo()
	require.Equal(t, common.TracerouteDriverInfo{
		SupportsParallel: false,
	}, info)
}
func TestTCPDriverTwoHops(t *testing.T) {
	config, driver, mockSink, mockSource := initTest(t)

	// *** TTL=1 -- get back an ICMP TTL exceeded
	mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).DoAndReturn(func(buf []byte, addrPort netip.AddrPort) error {
		parseSynAndExpectIDs(t, config, driver.basePacketID+1, driver.seqNum, buf)
		require.True(t, config.Target.Equal(addrPort.Addr().AsSlice()))
		require.Equal(t, config.DestPort, addrPort.Port())
		return nil
	})

	// trigger the mock
	err := driver.SendProbe(1)
	require.NoError(t, err)

	// make the source return an ICMP TTL exceeded
	hopIP := net.ParseIP("42.42.42.42")
	icmpResp := mockICMPResp(t, config, hopIP, driver.basePacketID, 1, packets.TCPInfo{
		SrcPort: config.srcPort,
		DstPort: config.DestPort,
		Seq:     driver.seqNum,
	})

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

	// *** TTL=2 -- get back a SYNACK
	mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).DoAndReturn(func(buf []byte, addrPort netip.AddrPort) error {
		parseSynAndExpectIDs(t, config, driver.basePacketID+2, driver.seqNum, buf)
		require.True(t, config.Target.Equal(addrPort.Addr().AsSlice()))
		require.Equal(t, config.DestPort, addrPort.Port())
		return nil
	})

	// send the second packet
	driver.SendProbe(2)

	// return synack
	mockSource.EXPECT().SetReadDeadline(gomock.Any()).Return(nil)
	ackPacket := mockTCPResp(t, config, true, true, false, driver.seqNum)
	mockRead(mockSource, ackPacket)

	probeResp, err = driver.ReceiveProbe(1 * time.Second)
	require.NoError(t, err)
	require.Equal(t, uint8(2), probeResp.TTL)
	require.True(t, config.Target.Equal(probeResp.IP.AsSlice()))
	require.True(t, probeResp.IsDest)
	require.False(t, probeResp.IsTerminal)
	require.Zero(t, probeResp.ICMPType)
	require.Zero(t, probeResp.ICMPCode)
}

func TestTCPDriverICMPResponses(t *testing.T) {
	for _, mode := range []struct {
		name  string
		paris bool
	}{
		{name: "regular"},
		{name: "paris", paris: true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			for _, tt := range []struct {
				name     string
				icmpType uint8
				icmpCode uint8
				terminal bool
			}{
				{name: "time_exceeded", icmpType: 11},
				{name: "net_unreachable", icmpType: 3, icmpCode: 0, terminal: true},
				{name: "host_unreachable", icmpType: 3, icmpCode: 1, terminal: true},
				{name: "port_unreachable", icmpType: 3, icmpCode: 3, terminal: true},
				{name: "fragmentation_needed", icmpType: 3, icmpCode: 4, terminal: true},
				{name: "admin_prohibited", icmpType: 3, icmpCode: 13, terminal: true},
			} {
				t.Run(tt.name, func(t *testing.T) {
					config, driver, mockSink, mockSource := initTest(t)
					config.ParisTracerouteMode = mode.paris
					mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(nil)
					require.NoError(t, driver.SendProbe(2))
					probe, err := driver.getLastSentProbe()
					require.NoError(t, err)

					hopIP := net.ParseIP("42.42.42.42")
					// The reply contains only the quoted IP header and first 8 TCP bytes.
					packet := mockICMPRespWithTypeCode(t, config, hopIP, probe.packetID-2, 2, packets.TCPInfo{
						SrcPort: config.srcPort,
						DstPort: config.DestPort,
						Seq:     probe.seqNum,
					}, layers.CreateICMPv4TypeCode(tt.icmpType, tt.icmpCode))
					mockSource.EXPECT().SetReadDeadline(gomock.Any()).Return(nil)
					mockRead(mockSource, packet)

					response, err := driver.ReceiveProbe(time.Second)
					require.NoError(t, err)
					require.Equal(t, uint8(2), response.TTL)
					require.Equal(t, netip.MustParseAddr("42.42.42.42"), response.IP)
					require.Positive(t, response.RTT)
					require.False(t, response.IsDest)
					require.Equal(t, tt.terminal, response.IsTerminal)
					require.Equal(t, tt.icmpType, response.ICMPType)
					require.Equal(t, tt.icmpCode, response.ICMPCode)
					hops, err := common.ToHops(common.TracerouteParams{MinTTL: 2}, []*common.ProbeResponse{response})
					require.NoError(t, err)
					require.Equal(t, tt.icmpType, hops[0].ICMPType)
					require.Equal(t, tt.icmpCode, hops[0].ICMPCode)
				})
			}
		})
	}
}

func TestTCPDriverICMPDestinationUnreachableMismatch(t *testing.T) {
	for _, tt := range []struct {
		name      string
		loosenSrc bool
		wantMatch bool
	}{
		{name: "source_ip"},
		{name: "destination_ip"},
		{name: "packet_id"},
		{name: "source_port"},
		{name: "destination_port"},
		{name: "sequence"},
		{name: "no_probe"},
		{name: "short_tcp"},
		{name: "short_ip"},
		{name: "other_icmp_type"},
		{name: "other_time_exceeded_code"},
		{name: "loose_source_ip", loosenSrc: true, wantMatch: true},
		{name: "loose_source_port", loosenSrc: true, wantMatch: true},
		{name: "loose_destination_ip", loosenSrc: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			config, driver, mockSink, mockSource := initTest(t)
			config.LoosenICMPSrc = tt.loosenSrc
			if tt.name != "no_probe" {
				mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(nil)
				require.NoError(t, driver.SendProbe(1))
			}
			replyConfig := *config
			packetID := driver.basePacketID
			tcpInfo := packets.TCPInfo{SrcPort: config.srcPort, DstPort: config.DestPort, Seq: driver.seqNum}
			typeCode := layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, 0)
			switch tt.name {
			case "source_ip", "loose_source_ip":
				replyConfig.srcIP = net.ParseIP("8.8.8.8")
			case "destination_ip", "loose_destination_ip":
				replyConfig.Target = net.ParseIP("8.8.8.8")
			case "packet_id":
				packetID++
			case "source_port", "loose_source_port":
				tcpInfo.SrcPort++
			case "destination_port":
				tcpInfo.DstPort++
			case "sequence":
				tcpInfo.Seq++
			case "other_icmp_type":
				typeCode = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeRedirect, 0)
			case "other_time_exceeded_code":
				typeCode = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeTimeExceeded, layers.ICMPv4CodeFragmentReassemblyTimeExceeded)
			}
			packet := mockICMPRespWithTypeCode(t, &replyConfig, net.ParseIP("42.42.42.42"), packetID, 1, tcpInfo, typeCode)
			if tt.name == "short_tcp" || tt.name == "short_ip" {
				parser := packets.NewFrameParser()
				require.NoError(t, parser.Parse(packet))
				payload := parser.ICMP4.Payload
				if tt.name == "short_tcp" {
					payload = payload[:27] // IP header and only 7 TCP bytes
				} else {
					payload = payload[:19] // incomplete IP header
				}
				buf := gopacket.NewSerializeBuffer()
				require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
					&parser.IP4, &parser.ICMP4, gopacket.Payload(payload)))
				packet = buf.Bytes()
			}
			mockSource.EXPECT().SetReadDeadline(gomock.Any()).Return(nil)
			mockRead(mockSource, packet)

			response, err := driver.ReceiveProbe(time.Second)
			if tt.wantMatch {
				require.NoError(t, err)
				require.True(t, response.IsTerminal)
				return
			}
			require.Nil(t, response)
			if tt.name == "short_tcp" || tt.name == "short_ip" {
				var badPacket *common.BadPacketError
				require.ErrorAs(t, err, &badPacket)
			} else {
				require.ErrorIs(t, err, common.ErrPacketDidNotMatchTraceroute)
			}
		})
	}
}

func TestTCPTracerouteStopsAtUnreachableHop(t *testing.T) {
	config, driver, mockSink, mockSource := initTest(t)
	hopIPs := []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")}
	for i, hopIP := range hopIPs {
		ttl := uint8(i + 1)
		mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).DoAndReturn(func(buf []byte, _ netip.AddrPort) error {
			parseSynAndExpectIDs(t, config, driver.basePacketID+uint16(ttl), driver.seqNum, buf)
			return nil
		})
		typeCode := layers.CreateICMPv4TypeCode(layers.ICMPv4TypeTimeExceeded, 0)
		if ttl == 2 {
			typeCode = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, 0)
		}
		packet := mockICMPRespWithTypeCode(t, config, hopIP, driver.basePacketID, ttl, packets.TCPInfo{
			SrcPort: config.srcPort, DstPort: config.DestPort, Seq: driver.seqNum,
		}, typeCode)
		mockSource.EXPECT().SetReadDeadline(gomock.Any()).Return(nil)
		mockRead(mockSource, packet)
	}
	// Any attempt to send a third probe fails the mock expectations.
	params := common.TracerouteSerialParams{TracerouteParams: common.TracerouteParams{
		MinTTL: 1, MaxTTL: 5, TracerouteTimeout: time.Second, PollFrequency: time.Millisecond,
	}}
	responses, err := common.TracerouteSerial(context.Background(), driver, params)
	require.NoError(t, err)
	hops, err := common.ToHops(params.TracerouteParams, responses)
	require.NoError(t, err)
	require.Len(t, hops, 2)
	for i, hop := range hops {
		require.Equal(t, i+1, hop.TTL)
		require.True(t, hopIPs[i].Equal(hop.IPAddress))
		require.False(t, hop.IsDest)
	}
	require.Equal(t, uint8(3), hops[1].ICMPType)
	require.Equal(t, uint8(0), hops[1].ICMPCode)
	run := result.TracerouteRun{Hops: hops}
	require.Nil(t, run.GetDestinationHop())
	results := result.Results{Traceroute: result.Traceroute{Runs: []result.TracerouteRun{run}}}
	results.Normalize()
	require.True(t, hops[1].Reachable)
}

// timestampedMockSource wraps a MockSource with a fixed kernel capture timestamp,
// simulating a Source implementing packets.TimestampedSource.
type timestampedMockSource struct {
	*packets.MockSource
	ts time.Time
}

func (t *timestampedMockSource) LastPacketTimestamp() (time.Time, bool) {
	return t.ts, true
}

var _ packets.Source = &timestampedMockSource{}
var _ packets.TimestampedSource = &timestampedMockSource{}

func TestTCPDriverUsesKernelTimestampForRTT(t *testing.T) {
	packets.RandomizePacketIDBase()

	ctrl := gomock.NewController(t)
	rawSource := packets.NewMockSource(ctrl)
	mockSink := packets.NewMockSink(ctrl)

	config := NewTCPv4(
		net.ParseIP("1.2.3.4"),
		80,
		1,
		30,
		10*time.Millisecond,
		1*time.Second,
		false,
		false,
	)
	config.srcIP = net.ParseIP("5.6.7.8")
	config.srcPort = 12345

	source := &timestampedMockSource{MockSource: rawSource}
	driver := newTCPDriver(config, mockSink, source)

	mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(nil)
	require.NoError(t, driver.SendProbe(1))
	afterSend := time.Now()

	// the kernel timestamp is set just after the probe was sent, implying a small,
	// bounded RTT -- regardless of how long the simulated Read() delivery takes.
	source.ts = afterSend.Add(20 * time.Millisecond)

	ackPacket := mockTCPResp(t, config, true, true, false, driver.seqNum)
	rawSource.EXPECT().SetReadDeadline(gomock.Any()).Return(nil)
	rawSource.EXPECT().Read(gomock.Any()).DoAndReturn(func(buf []byte) (int, error) {
		// simulate delivery arriving well after the packet was actually captured
		time.Sleep(300 * time.Millisecond)
		return copy(buf, ackPacket), nil
	})

	probeResp, err := driver.ReceiveProbe(1 * time.Second)
	require.NoError(t, err)
	require.True(t, probeResp.IsDest)

	// if the driver used delivery time (time.Now()) instead of the kernel timestamp,
	// RTT would be at least the 300ms artificial delivery delay.
	require.GreaterOrEqual(t, probeResp.RTT, time.Duration(0))
	require.Less(t, probeResp.RTT, 250*time.Millisecond,
		"RTT should be computed from the kernel capture timestamp, not delayed delivery time")
}

func TestTCPDriverRST(t *testing.T) {
	config, driver, mockSink, mockSource := initTest(t)

	// *** TTL=1 -- get back a RST
	mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).DoAndReturn(func(buf []byte, addrPort netip.AddrPort) error {
		parseSynAndExpectIDs(t, config, driver.basePacketID+1, driver.seqNum, buf)
		require.True(t, config.Target.Equal(addrPort.Addr().AsSlice()))
		require.Equal(t, config.DestPort, addrPort.Port())
		return nil
	})

	// send the second packet
	driver.SendProbe(1)

	// return rst
	mockSource.EXPECT().SetReadDeadline(gomock.Any()).Return(nil)
	// seqNum of 0 is okay because the RST does not have the ACK flag
	ackPacket := mockTCPResp(t, config, false, false, true, 0)

	mockRead(mockSource, ackPacket)

	probeResp, err := driver.ReceiveProbe(1 * time.Second)
	require.NoError(t, err)
	require.Equal(t, uint8(1), probeResp.TTL)
	require.True(t, config.Target.Equal(probeResp.IP.AsSlice()))
	require.True(t, probeResp.IsDest)
}

func TestTCPDriverICMPMismatchedIP(t *testing.T) {
	config, driver, mockSink, mockSource := initTest(t)
	mockSource.EXPECT().SetReadDeadline(gomock.Any()).AnyTimes().Return(nil)
	mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(nil)

	// trigger the mock
	err := driver.SendProbe(1)
	require.NoError(t, err)

	// *** CASE 1: mismatched src IP
	hopIP := net.ParseIP("42.42.42.42")
	badConfig := *config
	badConfig.srcIP = net.ParseIP("8.8.8.8")
	tcpInfo := packets.TCPInfo{
		SrcPort: config.srcPort,
		DstPort: config.DestPort,
		Seq:     driver.seqNum,
	}
	icmpResp := mockICMPResp(t, &badConfig, hopIP, driver.basePacketID, 1, tcpInfo)

	mockRead(mockSource, icmpResp)

	probeResp, err := driver.ReceiveProbe(1 * time.Second)
	require.Nil(t, probeResp)
	require.ErrorIs(t, err, common.ErrPacketDidNotMatchTraceroute)

	// *** CASE 2: mismatched dest IP
	hopIP = net.ParseIP("42.42.42.42")
	badConfig = *config
	badConfig.Target = net.ParseIP("8.8.8.8")
	icmpResp = mockICMPResp(t, &badConfig, hopIP, driver.basePacketID, 1, tcpInfo)

	mockRead(mockSource, icmpResp)

	probeResp, err = driver.ReceiveProbe(1 * time.Second)
	require.Nil(t, probeResp)
	require.ErrorIs(t, err, common.ErrPacketDidNotMatchTraceroute)

	// *** CASE 3: mismatched packet ID
	icmpResp = mockICMPResp(t, config, hopIP, driver.basePacketID+123, 1, tcpInfo)

	mockRead(mockSource, icmpResp)

	probeResp, err = driver.ReceiveProbe(1 * time.Second)
	require.Nil(t, probeResp)
	require.ErrorIs(t, err, common.ErrPacketDidNotMatchTraceroute)
}
func TestTCPDriverICMPMismatchedTCPInfo(t *testing.T) {
	config, driver, mockSink, mockSource := initTest(t)
	mockSource.EXPECT().SetReadDeadline(gomock.Any()).AnyTimes().Return(nil)
	mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(nil)
	// trigger the mock
	err := driver.SendProbe(1)
	require.NoError(t, err)

	tcpInfo := packets.TCPInfo{
		SrcPort: config.srcPort,
		DstPort: config.DestPort,
		Seq:     driver.seqNum,
	}

	// *** get back an ICMP TTL exceeded, but for the wrong seq num
	hopIP := net.ParseIP("42.42.42.42")
	badTCPInfo := tcpInfo
	badTCPInfo.Seq++
	icmpResp := mockICMPResp(t, config, hopIP, driver.basePacketID, 1, badTCPInfo)

	mockRead(mockSource, icmpResp)

	probeResp, err := driver.ReceiveProbe(1 * time.Second)
	require.Nil(t, probeResp)
	require.ErrorIs(t, err, common.ErrPacketDidNotMatchTraceroute)

	// *** get back an ICMP TTL exceeded, but for the wrong srcPort
	badTCPInfo = tcpInfo
	badTCPInfo.SrcPort++
	icmpResp = mockICMPResp(t, config, hopIP, driver.basePacketID, 1, badTCPInfo)

	mockRead(mockSource, icmpResp)

	probeResp, err = driver.ReceiveProbe(1 * time.Second)
	require.Nil(t, probeResp)
	require.ErrorIs(t, err, common.ErrPacketDidNotMatchTraceroute)

	// *** get back an ICMP TTL exceeded, but for the wrong dstPort
	badTCPInfo = tcpInfo
	badTCPInfo.DstPort++
	icmpResp = mockICMPResp(t, config, hopIP, driver.basePacketID, 1, badTCPInfo)

	mockRead(mockSource, icmpResp)

	probeResp, err = driver.ReceiveProbe(1 * time.Second)
	require.Nil(t, probeResp)
	require.ErrorIs(t, err, common.ErrPacketDidNotMatchTraceroute)
}

func TestTCPDriverMismatchedSynackInfo(t *testing.T) {
	config, driver, mockSink, mockSource := initTest(t)
	mockSource.EXPECT().SetReadDeadline(gomock.Any()).AnyTimes().Return(nil)
	mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).AnyTimes().Return(nil)

	// trigger the mock
	err := driver.SendProbe(2)
	require.NoError(t, err)

	// *** get back a SYNACK, but for the wrong seq num
	ackPacket := mockTCPResp(t, config, true, true, false, driver.seqNum+1)
	mockRead(mockSource, ackPacket)

	probeResp, err := driver.ReceiveProbe(1 * time.Second)
	require.Nil(t, probeResp)
	require.ErrorIs(t, err, common.ErrPacketDidNotMatchTraceroute)

	// *** get back a SYNACK, but for the wrong port
	badConfig := *config
	badConfig.srcPort++
	ackPacket = mockTCPResp(t, &badConfig, true, true, false, driver.seqNum)
	mockRead(mockSource, ackPacket)

	probeResp, err = driver.ReceiveProbe(1 * time.Second)
	require.Nil(t, probeResp)
	require.ErrorIs(t, err, common.ErrPacketDidNotMatchTraceroute)

	// *** get back a SYNACK, but for the wrong dest port
	badConfig = *config
	badConfig.DestPort++
	ackPacket = mockTCPResp(t, &badConfig, true, true, false, driver.seqNum)
	mockRead(mockSource, ackPacket)

	probeResp, err = driver.ReceiveProbe(1 * time.Second)
	require.Nil(t, probeResp)
	require.ErrorIs(t, err, common.ErrPacketDidNotMatchTraceroute)
}

func TestTCPDriverMismatchedSynackIP(t *testing.T) {
	config, driver, mockSink, mockSource := initTest(t)
	mockSource.EXPECT().SetReadDeadline(gomock.Any()).AnyTimes().Return(nil)
	mockSink.EXPECT().WriteTo(gomock.Any(), gomock.Any()).AnyTimes().Return(nil)

	// trigger the mock
	err := driver.SendProbe(2)
	require.NoError(t, err)

	// *** get back a SYNACK, but for the wrong srcIP
	badConfig := *config
	badConfig.srcIP = net.ParseIP("8.8.8.8")
	ackPacket := mockTCPResp(t, &badConfig, true, true, false, driver.seqNum)
	mockRead(mockSource, ackPacket)

	probeResp, err := driver.ReceiveProbe(1 * time.Second)
	require.Nil(t, probeResp)
	require.ErrorIs(t, err, common.ErrPacketDidNotMatchTraceroute)

	// *** get back a SYNACK, but for the wrong dest IP
	badConfig = *config
	badConfig.Target = net.ParseIP("8.8.8.8")
	ackPacket = mockTCPResp(t, &badConfig, true, true, false, driver.seqNum)
	mockRead(mockSource, ackPacket)

	probeResp, err = driver.ReceiveProbe(1 * time.Second)
	require.Nil(t, probeResp)
	require.ErrorIs(t, err, common.ErrPacketDidNotMatchTraceroute)
}
