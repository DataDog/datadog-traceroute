// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package icmpecho

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/google/gopacket/layers"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/log"
	"github.com/DataDog/datadog-traceroute/packets"
)

type probeData struct {
	sendTime time.Time
	ttl      uint8
	seqNum   uint16
}

type icmpDriver struct {
	config *ICMPv4

	sink packets.Sink

	source packets.Source
	buffer []byte
	parser *packets.FrameParser

	// mu guards against concurrent access to sentProbes
	mu         sync.Mutex
	sentProbes map[uint16]probeData // keyed by sequence number
}

func newICMPDriver(config *ICMPv4, sink packets.Sink, source packets.Source) *icmpDriver {
	return &icmpDriver{
		config: config,

		sink: sink,

		source: source,
		buffer: make([]byte, 1024),
		parser: packets.NewFrameParser(),

		sentProbes: make(map[uint16]probeData),
	}
}

func (d *icmpDriver) storeProbe(seqNum uint16, data probeData) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	// refuse to store it if we somehow would overwrite
	if _, ok := d.sentProbes[seqNum]; ok {
		return false
	}

	d.sentProbes[seqNum] = data
	return true
}

func (d *icmpDriver) findMatchingProbe(seqNum uint16) (probeData, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	data, ok := d.sentProbes[seqNum]
	return data, ok
}

func (d *icmpDriver) getLocalAddr() netip.Addr {
	addr, _ := common.UnmappedAddrFromSlice(d.config.srcIP)
	return addr
}

func (d *icmpDriver) getTargetAddr() netip.Addr {
	addr, _ := common.UnmappedAddrFromSlice(d.config.Target)
	return addr
}

var _ common.TracerouteDriver = &icmpDriver{}

// GetDriverInfo returns metadata about this driver
func (d *icmpDriver) GetDriverInfo() common.TracerouteDriverInfo {
	return common.TracerouteDriverInfo{
		SupportsParallel: true,
	}
}

// SendProbe sends a traceroute packet with a specific TTL
func (d *icmpDriver) SendProbe(ttl uint8) error {
	// Use TTL as the sequence number to make matching easier
	seqNum := uint16(ttl)

	buffer, err := d.config.createRawICMPEchoBuffer(d.config.srcIP, d.config.Target, ttl, d.config.icmpID, seqNum)
	if err != nil {
		return fmt.Errorf("icmpDriver SendProbe failed to createRawICMPEchoBuffer: %w", err)
	}

	data := probeData{sendTime: time.Now(), ttl: ttl, seqNum: seqNum}
	log.Tracef("sending ICMP probe with ttl=%d, icmpID=%d, seqNum=%d", ttl, d.config.icmpID, seqNum)
	ok := d.storeProbe(seqNum, data)
	if !ok {
		return fmt.Errorf("icmpDriver SendProbe tried to send the same seqNum twice for ttl=%d", ttl)
	}

	// For ICMP, we use port 0 since ICMP doesn't use ports
	err = d.sink.WriteTo(buffer, netip.AddrPortFrom(d.getTargetAddr(), 0))
	if err != nil {
		return fmt.Errorf("icmpDriver SendProbe failed to write packet: %w", err)
	}
	return nil
}

// ReceiveProbe polls to get a traceroute response with a timeout.
func (d *icmpDriver) ReceiveProbe(timeout time.Duration) (*common.ProbeResponse, error) {
	err := d.source.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return nil, fmt.Errorf("icmpDriver failed to SetReadDeadline: %w", err)
	}
	err = packets.ReadAndParse(d.source, d.buffer, d.parser)
	if err != nil {
		return nil, err
	}

	return d.handleProbeLayers()
}

func (d *icmpDriver) handleProbeLayers() (*common.ProbeResponse, error) {
	ipPair, err := d.parser.GetIPPair()
	if err != nil {
		return nil, fmt.Errorf("icmpDriver failed to get IP pair: %w", err)
	}

	var probe probeData
	var isDest bool

	switch d.parser.GetTransportLayer() {
	case layers.LayerTypeICMPv4:
		return d.handleICMPv4(ipPair)
	case layers.LayerTypeICMPv6:
		return d.handleICMPv6(ipPair)
	default:
		return nil, common.ErrPacketDidNotMatchTraceroute
	}

	if probe == (probeData{}) {
		return nil, common.ErrPacketDidNotMatchTraceroute
	}
	rtt := time.Since(probe.sendTime)

	return &common.ProbeResponse{
		TTL:    probe.ttl,
		IP:     ipPair.SrcAddr,
		RTT:    rtt,
		IsDest: isDest,
	}, nil
}

func (d *icmpDriver) handleICMPv4(ipPair packets.IPPair) (*common.ProbeResponse, error) {
	typeCode := d.parser.ICMP4.TypeCode

	// Check if this is an Echo Reply (destination reached)
	if typeCode == layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0) {
		// Verify the ICMP ID matches
		if d.parser.ICMP4.Id != d.config.icmpID {
			log.Tracef("icmpDriver ignored Echo Reply with different ID: expected=%d, actual=%d", d.config.icmpID, d.parser.ICMP4.Id)
			return nil, common.ErrPacketDidNotMatchTraceroute
		}

		seqNum := d.parser.ICMP4.Seq
		probe, ok := d.findMatchingProbe(seqNum)
		if !ok {
			log.Warnf("icmpDriver couldn't find probe matching seqNum=%d", seqNum)
			return nil, common.ErrPacketDidNotMatchTraceroute
		}

		rtt := time.Since(probe.sendTime)
		return &common.ProbeResponse{
			TTL:    probe.ttl,
			IP:     ipPair.SrcAddr,
			RTT:    rtt,
			IsDest: true,
		}, nil
	}

	// Check if this is a TTL Exceeded or Destination Unreachable
	if !d.parser.IsTTLExceeded() && !d.parser.IsDestinationUnreachable() {
		return nil, common.ErrPacketDidNotMatchTraceroute
	}

	icmpInfo, err := d.parser.GetICMPInfo()
	if err != nil {
		return nil, &common.BadPacketError{Err: fmt.Errorf("icmpDriver failed to get ICMP info: %w", err)}
	}

	// Verify the inner packet was destined for our target
	if icmpInfo.ICMPPair.DstAddr != d.getTargetAddr() {
		log.Tracef("icmpDriver ignored ICMP packet with different destination: expected=%s, actual=%s", d.getTargetAddr(), icmpInfo.ICMPPair.DstAddr)
		return nil, common.ErrPacketDidNotMatchTraceroute
	}

	// Parse the inner ICMP Echo Request to get the sequence number
	innerICMP, err := parseInnerICMPv4(icmpInfo.Payload)
	if err != nil {
		return nil, &common.BadPacketError{Err: fmt.Errorf("icmpDriver failed to parse inner ICMP: %w", err)}
	}

	// Verify the ICMP ID matches
	if innerICMP.ID != d.config.icmpID {
		log.Tracef("icmpDriver ignored ICMP packet with different ID: expected=%d, actual=%d", d.config.icmpID, innerICMP.ID)
		return nil, common.ErrPacketDidNotMatchTraceroute
	}

	probe, ok := d.findMatchingProbe(innerICMP.Seq)
	if !ok {
		log.Warnf("icmpDriver couldn't find probe matching seqNum=%d", innerICMP.Seq)
		return nil, common.ErrPacketDidNotMatchTraceroute
	}

	rtt := time.Since(probe.sendTime)
	return &common.ProbeResponse{
		TTL:    probe.ttl,
		IP:     ipPair.SrcAddr,
		RTT:    rtt,
		IsDest: ipPair.SrcAddr == d.getTargetAddr(),
	}, nil
}

func (d *icmpDriver) handleICMPv6(ipPair packets.IPPair) (*common.ProbeResponse, error) {
	typeCode := d.parser.ICMP6.TypeCode

	// Check if this is an Echo Reply (destination reached)
	if typeCode == layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoReply, 0) {
		// For ICMPv6, ID and Seq are in the payload
		innerICMP, err := parseInnerICMPv6EchoReply(d.parser.ICMP6.Payload)
		if err != nil {
			return nil, &common.BadPacketError{Err: fmt.Errorf("icmpDriver failed to parse ICMPv6 Echo Reply: %w", err)}
		}

		if innerICMP.ID != d.config.icmpID {
			log.Tracef("icmpDriver ignored ICMPv6 Echo Reply with different ID: expected=%d, actual=%d", d.config.icmpID, innerICMP.ID)
			return nil, common.ErrPacketDidNotMatchTraceroute
		}

		probe, ok := d.findMatchingProbe(innerICMP.Seq)
		if !ok {
			log.Warnf("icmpDriver couldn't find probe matching seqNum=%d", innerICMP.Seq)
			return nil, common.ErrPacketDidNotMatchTraceroute
		}

		rtt := time.Since(probe.sendTime)
		return &common.ProbeResponse{
			TTL:    probe.ttl,
			IP:     ipPair.SrcAddr,
			RTT:    rtt,
			IsDest: true,
		}, nil
	}

	// Check if this is a TTL Exceeded or Destination Unreachable
	if !d.parser.IsTTLExceeded() && !d.parser.IsDestinationUnreachable() {
		return nil, common.ErrPacketDidNotMatchTraceroute
	}

	icmpInfo, err := d.parser.GetICMPInfo()
	if err != nil {
		return nil, &common.BadPacketError{Err: fmt.Errorf("icmpDriver failed to get ICMP info: %w", err)}
	}

	// Verify the inner packet was destined for our target
	if icmpInfo.ICMPPair.DstAddr != d.getTargetAddr() {
		log.Tracef("icmpDriver ignored ICMPv6 packet with different destination: expected=%s, actual=%s", d.getTargetAddr(), icmpInfo.ICMPPair.DstAddr)
		return nil, common.ErrPacketDidNotMatchTraceroute
	}

	// Parse the inner ICMPv6 Echo Request to get the sequence number
	innerICMP, err := parseInnerICMPv6(icmpInfo.Payload)
	if err != nil {
		return nil, &common.BadPacketError{Err: fmt.Errorf("icmpDriver failed to parse inner ICMPv6: %w", err)}
	}

	// Verify the ICMP ID matches
	if innerICMP.ID != d.config.icmpID {
		log.Tracef("icmpDriver ignored ICMPv6 packet with different ID: expected=%d, actual=%d", d.config.icmpID, innerICMP.ID)
		return nil, common.ErrPacketDidNotMatchTraceroute
	}

	probe, ok := d.findMatchingProbe(innerICMP.Seq)
	if !ok {
		log.Warnf("icmpDriver couldn't find probe matching seqNum=%d", innerICMP.Seq)
		return nil, common.ErrPacketDidNotMatchTraceroute
	}

	rtt := time.Since(probe.sendTime)
	return &common.ProbeResponse{
		TTL:    probe.ttl,
		IP:     ipPair.SrcAddr,
		RTT:    rtt,
		IsDest: ipPair.SrcAddr == d.getTargetAddr(),
	}, nil
}

// Close closes the icmpDriver
func (d *icmpDriver) Close() error {
	sinkErr := d.sink.Close()
	sourceErr := d.source.Close()
	return errors.Join(sinkErr, sourceErr)
}

// ICMPEchoInfo contains the parsed ICMP Echo Request/Reply ID and sequence number
type ICMPEchoInfo struct {
	ID  uint16
	Seq uint16
}

// parseInnerICMPv4 parses the first 8 bytes of an ICMP Echo Request from within an ICMP TTL Exceeded payload
func parseInnerICMPv4(payload []byte) (ICMPEchoInfo, error) {
	// ICMP header is at least 8 bytes: type(1) + code(1) + checksum(2) + id(2) + seq(2)
	if len(payload) < 8 {
		return ICMPEchoInfo{}, fmt.Errorf("parseInnerICMPv4: payload too short (%d bytes)", len(payload))
	}

	// Verify it's an Echo Request (type 8)
	if payload[0] != 8 {
		return ICMPEchoInfo{}, fmt.Errorf("parseInnerICMPv4: not an Echo Request (type=%d)", payload[0])
	}

	return ICMPEchoInfo{
		ID:  uint16(payload[4])<<8 | uint16(payload[5]),
		Seq: uint16(payload[6])<<8 | uint16(payload[7]),
	}, nil
}

// parseInnerICMPv6 parses the first 8 bytes of an ICMPv6 Echo Request from within an ICMPv6 TTL Exceeded payload
func parseInnerICMPv6(payload []byte) (ICMPEchoInfo, error) {
	// ICMPv6 header is at least 8 bytes: type(1) + code(1) + checksum(2) + id(2) + seq(2)
	if len(payload) < 8 {
		return ICMPEchoInfo{}, fmt.Errorf("parseInnerICMPv6: payload too short (%d bytes)", len(payload))
	}

	// Verify it's an Echo Request (type 128)
	if payload[0] != 128 {
		return ICMPEchoInfo{}, fmt.Errorf("parseInnerICMPv6: not an Echo Request (type=%d)", payload[0])
	}

	return ICMPEchoInfo{
		ID:  uint16(payload[4])<<8 | uint16(payload[5]),
		Seq: uint16(payload[6])<<8 | uint16(payload[7]),
	}, nil
}

// parseInnerICMPv6EchoReply parses the ID and Seq from an ICMPv6 Echo Reply payload
// In ICMPv6 Echo Reply, the payload starts with ID(2) + Seq(2)
func parseInnerICMPv6EchoReply(payload []byte) (ICMPEchoInfo, error) {
	if len(payload) < 4 {
		return ICMPEchoInfo{}, fmt.Errorf("parseInnerICMPv6EchoReply: payload too short (%d bytes)", len(payload))
	}

	return ICMPEchoInfo{
		ID:  uint16(payload[0])<<8 | uint16(payload[1]),
		Seq: uint16(payload[2])<<8 | uint16(payload[3]),
	}, nil
}
