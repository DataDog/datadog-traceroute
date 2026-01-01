// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

// Package icmpecho adds an ICMP Echo traceroute implementation
package icmpecho

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type (
	// ICMPv4 encapsulates the data needed to run
	// an ICMPv4 traceroute using ICMP Echo Request packets
	ICMPv4 struct {
		Target  net.IP
		srcIP   net.IP // calculated internally
		MinTTL  uint8
		MaxTTL  uint8
		Delay   time.Duration // delay between sending packets
		Timeout time.Duration // full timeout for all packets
		buffer  gopacket.SerializeBuffer
		// UseWindowsDriver controls whether to use driver-based packet capture (Windows)
		UseWindowsDriver bool
		// icmpID is the ICMP identifier used for all packets in this traceroute
		icmpID uint16
	}
)

// NewICMPv4 initializes a new ICMPv4 traceroute instance
func NewICMPv4(target net.IP, minTTL uint8, maxTTL uint8, delay time.Duration, timeout time.Duration, useDriver bool) *ICMPv4 {
	buffer := gopacket.NewSerializeBufferExpectedSize(28, 0) // IP (20) + ICMP (8)

	return &ICMPv4{
		Target:           target,
		MinTTL:           minTTL,
		MaxTTL:           maxTTL,
		Delay:            delay,
		Timeout:          timeout,
		buffer:           buffer,
		UseWindowsDriver: useDriver,
		icmpID:           0, // will be set in createRawICMPEchoBuffer
	}
}

// createRawICMPEchoBuffer creates a raw ICMP Echo Request packet with the specified parameters.
// The sequence number is set to the TTL value to help match responses.
func (i *ICMPv4) createRawICMPEchoBuffer(sourceIP net.IP, destIP net.IP, ttl uint8, icmpID uint16, seqNum uint16) ([]byte, error) {
	// clear the gopacket.SerializeBuffer
	if len(i.buffer.Bytes()) > 0 {
		if err := i.buffer.Clear(); err != nil {
			i.buffer = gopacket.NewSerializeBuffer()
		}
	}

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	// Small payload for the ICMP Echo Request
	payload := []byte("NSMNC\x00\x00\x00")
	payload[6] = byte((seqNum >> 8) & 0xff)
	payload[7] = byte(seqNum & 0xff)

	if destIP.To4() != nil {
		// IPv4
		ipv4Layer := &layers.IPv4{
			Version:  4,
			Length:   20,
			TTL:      ttl,
			Id:       41821 + uint16(ttl),
			Protocol: layers.IPProtocolICMPv4,
			DstIP:    destIP,
			SrcIP:    sourceIP,
			Flags:    layers.IPv4DontFragment,
		}

		icmpv4Layer := &layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
			Id:       icmpID,
			Seq:      seqNum,
		}

		err := gopacket.SerializeLayers(i.buffer, opts,
			ipv4Layer,
			icmpv4Layer,
			gopacket.Payload(payload),
		)
		if err != nil {
			return nil, err
		}
	} else {
		// IPv6
		ipv6Layer := &layers.IPv6{
			Version:    6,
			HopLimit:   ttl,
			NextHeader: layers.IPProtocolICMPv6,
			SrcIP:      sourceIP,
			DstIP:      destIP,
		}

		icmpv6Layer := &layers.ICMPv6{
			TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
		}
		icmpv6Layer.SetNetworkLayerForChecksum(ipv6Layer)

		// ICMPv6 Echo Request payload format: 2 bytes ID + 2 bytes Seq + data
		icmpv6Payload := make([]byte, 4+len(payload))
		icmpv6Payload[0] = byte((icmpID >> 8) & 0xff)
		icmpv6Payload[1] = byte(icmpID & 0xff)
		icmpv6Payload[2] = byte((seqNum >> 8) & 0xff)
		icmpv6Payload[3] = byte(seqNum & 0xff)
		copy(icmpv6Payload[4:], payload)

		err := gopacket.SerializeLayers(i.buffer, opts,
			ipv6Layer,
			icmpv6Layer,
			gopacket.Payload(icmpv6Payload),
		)
		if err != nil {
			return nil, err
		}
	}

	return i.buffer.Bytes(), nil
}
