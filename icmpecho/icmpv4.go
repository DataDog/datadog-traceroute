// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

// Package icmpecho adds an ICMP Echo traceroute implementation to the agent
package icmpecho

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type (
	// ICMPv4 encapsulates the data needed to run
	// an ICMPv4 traceroute
	ICMPv4 struct {
		Target  net.IP
		srcIP   net.IP // calculated internally
		MinTTL  uint8
		MaxTTL  uint8
		Delay   time.Duration // delay between sending packets
		Timeout time.Duration // full timeout for all packets
		// UseWindowsDriver controls whether to use driver-based packet capture (Windows)
		UseWindowsDriver bool
		buffer           gopacket.SerializeBuffer

		// identifier is used as the ICMP identifier field to match responses
		identifier uint16
		// seqBase is the base sequence number, TTL is added to this
		seqBase uint16
	}
)

// NewICMPv4 initializes a new ICMPv4 traceroute instance
func NewICMPv4(target net.IP, minTTL uint8, maxTTL uint8, delay time.Duration, timeout time.Duration, useDriver bool) *ICMPv4 {
	buffer := gopacket.NewSerializeBufferExpectedSize(28, 0) // 20 IP + 8 ICMP

	return &ICMPv4{
		Target:           target,
		MinTTL:           minTTL,
		MaxTTL:           maxTTL,
		Delay:            delay,
		Timeout:          timeout,
		UseWindowsDriver: useDriver,
		buffer:           buffer,
	}
}

// Close doesn't do anything yet, but we should
// use this to close out long running sockets
// when we're done with a path test
func (i *ICMPv4) Close() error {
	return nil
}

// createRawICMPEchoBuffer creates an ICMP Echo Request packet with the specified parameters
func (i *ICMPv4) createRawICMPEchoBuffer(packetID uint16, ttl int) ([]byte, error) {
	ipLayer := &layers.IPv4{
		Version:  4,
		Length:   20,
		TTL:      uint8(ttl),
		Id:       packetID,
		Protocol: layers.IPProtocolICMPv4,
		DstIP:    i.Target,
		SrcIP:    i.srcIP,
	}

	// Use TTL as the sequence number offset for identification
	seqNum := i.seqBase + uint16(ttl)

	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       i.identifier,
		Seq:      seqNum,
	}

	// Payload contains the timestamp for RTT calculation (optional but useful)
	payload := gopacket.Payload([]byte("DATADOG"))

	// clear the gopacket.SerializeBuffer
	if len(i.buffer.Bytes()) > 0 {
		if err := i.buffer.Clear(); err != nil {
			i.buffer = gopacket.NewSerializeBuffer()
		}
	}
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(i.buffer, opts,
		ipLayer,
		icmpLayer,
		payload,
	)
	if err != nil {
		return nil, err
	}

	return i.buffer.Bytes(), nil
}
