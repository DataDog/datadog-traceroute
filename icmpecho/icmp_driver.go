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
	packetID uint16
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

	// basePacketID is used for the IP packet ID
	basePacketID uint16
}

var _ common.TracerouteDriver = &icmpDriver{}

func newICMPDriver(config *ICMPv4, sink packets.Sink, source packets.Source) *icmpDriver {
	basePacketID := packets.AllocPacketID(config.MaxTTL)

	return &icmpDriver{
		config: config,

		sink: sink,

		source: source,
		buffer: make([]byte, 1024),
		parser: packets.NewFrameParser(),

		sentProbes: make(map[uint16]probeData),

		basePacketID: basePacketID,
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

// GetDriverInfo returns metadata about this driver
func (d *icmpDriver) GetDriverInfo() common.TracerouteDriverInfo {
	return common.TracerouteDriverInfo{
		SupportsParallel: true,
	}
}

// SendProbe sends a traceroute packet with a specific TTL
func (d *icmpDriver) SendProbe(ttl uint8) error {
	packetID := d.basePacketID + uint16(ttl)
	seqNum := d.config.seqBase + uint16(ttl)

	buffer, err := d.config.createRawICMPEchoBuffer(packetID, int(ttl))
	if err != nil {
		return fmt.Errorf("icmpDriver SendProbe failed to createRawICMPEchoBuffer: %w", err)
	}

	data := probeData{
		sendTime: time.Now(),
		ttl:      ttl,
		packetID: packetID,
		seqNum:   seqNum,
	}
	log.Tracef("sending ICMP probe with ttl=%d, packetID=%d, seqNum=%d", ttl, packetID, seqNum)
	ok := d.storeProbe(seqNum, data)
	if !ok {
		return fmt.Errorf("icmpDriver SendProbe tried to send the same probe seqNum twice for ttl=%d", ttl)
	}

	// ICMP doesn't use ports, but the sink interface requires an AddrPort
	// Use port 0 as a placeholder
	target := netip.AddrPortFrom(d.getTargetAddr(), 0)
	err = d.sink.WriteTo(buffer, target)
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
		// Check for Echo Reply (destination reached)
		if d.parser.ICMP4.TypeCode.Type() == layers.ICMPv4TypeEchoReply {
			// Verify it's a response to our probe
			if d.parser.ICMP4.Id != d.config.identifier {
				log.Tracef("icmpDriver ignored Echo Reply with mismatched identifier: expected=%d, actual=%d",
					d.config.identifier, d.parser.ICMP4.Id)
				return nil, common.ErrPacketDidNotMatchTraceroute
			}

			seqNum := d.parser.ICMP4.Seq
			var ok bool
			probe, ok = d.findMatchingProbe(seqNum)
			if !ok {
				log.Warnf("couldn't find probe matching seqNum=%d", seqNum)
				return nil, common.ErrPacketDidNotMatchTraceroute
			}

			isDest = true
		} else if d.parser.IsTTLExceeded() || d.parser.IsDestinationUnreachable() {
			// TTL Exceeded or Destination Unreachable - intermediate hop or destination
			icmpInfo, err := d.parser.GetICMPInfo()
			if err != nil {
				return nil, &common.BadPacketError{Err: fmt.Errorf("icmpDriver failed to get ICMP info: %w", err)}
			}

			// Parse the embedded ICMP header from the payload
			icmpEchoInfo, err := parseICMPEchoFirstBytes(icmpInfo.Payload)
			if err != nil {
				return nil, &common.BadPacketError{Err: fmt.Errorf("icmpDriver failed to parse embedded ICMP: %w", err)}
			}

			// Verify the embedded ICMP identifier matches ours
			if icmpEchoInfo.ID != d.config.identifier {
				log.Tracef("icmpDriver ignored ICMP response with mismatched identifier: expected=%d, actual=%d",
					d.config.identifier, icmpEchoInfo.ID)
				return nil, common.ErrPacketDidNotMatchTraceroute
			}

			// Verify the embedded IP addresses match
			if icmpInfo.ICMPPair.SrcAddr != d.getLocalAddr() {
				log.Tracef("icmpDriver ignored ICMP response with mismatched src addr: expected=%s, actual=%s",
					d.getLocalAddr(), icmpInfo.ICMPPair.SrcAddr)
				return nil, common.ErrPacketDidNotMatchTraceroute
			}
			if icmpInfo.ICMPPair.DstAddr != d.getTargetAddr() {
				log.Tracef("icmpDriver ignored ICMP response with mismatched dst addr: expected=%s, actual=%s",
					d.getTargetAddr(), icmpInfo.ICMPPair.DstAddr)
				return nil, common.ErrPacketDidNotMatchTraceroute
			}

			seqNum := icmpEchoInfo.Seq
			var ok bool
			probe, ok = d.findMatchingProbe(seqNum)
			if !ok {
				log.Warnf("couldn't find probe matching seqNum=%d", seqNum)
				return nil, common.ErrPacketDidNotMatchTraceroute
			}

			// Destination Unreachable from the target means we reached it
			if d.parser.IsDestinationUnreachable() && ipPair.SrcAddr == d.getTargetAddr() {
				isDest = true
			}
		} else {
			return nil, common.ErrPacketDidNotMatchTraceroute
		}
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

// Close closes the icmpDriver
func (d *icmpDriver) Close() error {
	sinkErr := d.sink.Close()
	sourceErr := d.source.Close()
	return errors.Join(sinkErr, sourceErr)
}

// ICMPEchoInfo contains parsed ICMP Echo Request/Reply header fields
type ICMPEchoInfo struct {
	ID  uint16
	Seq uint16
}

// parseICMPEchoFirstBytes parses the ICMP Echo header from the payload
// ICMP header format: Type(1) + Code(1) + Checksum(2) + ID(2) + Seq(2)
// So ID is at offset 4 and Seq is at offset 6
func parseICMPEchoFirstBytes(payload []byte) (ICMPEchoInfo, error) {
	// Need at least 8 bytes for full ICMP Echo header
	if len(payload) < 8 {
		return ICMPEchoInfo{}, fmt.Errorf("ICMP payload too short: %d bytes", len(payload))
	}

	return ICMPEchoInfo{
		ID:  uint16(payload[4])<<8 | uint16(payload[5]),
		Seq: uint16(payload[6])<<8 | uint16(payload[7]),
	}, nil
}
