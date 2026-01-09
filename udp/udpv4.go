// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package udp adds a UDP traceroute implementation to the agent
package udp

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/DataDog/datadog-traceroute/icmp"
)

type (
	// UDPv4 encapsulates the data needed to run
	// a UDPv4 traceroute
	UDPv4 struct {
		Target     net.IP
		TargetPort uint16
		srcIP      net.IP // calculated internally
		srcPort    uint16 // calculated internally
		MinTTL     uint8
		MaxTTL     uint8
		Delay      time.Duration // delay between sending packets (not applicable if we go the serial send/receive route)
		Timeout    time.Duration // full timeout for all packets
		icmpParser icmp.Parser
		buffer     gopacket.SerializeBuffer

		// LoosenICMPSrc disables checking the source IP/port in ICMP payloads when enabled.
		// Reason: Some environments don't properly translate the payload of an ICMP TTL exceeded
		// packet meaning you can't trust the source address to correspond to your own private IP.
		LoosenICMPSrc bool
		// UseWindowsDriver controls whether to use driver-based packet capture (Windows)
		UseWindowsDriver bool
	}
)

// NewUDPv4 initializes a new UDPv4 traceroute instance
func NewUDPv4(target net.IP, targetPort uint16, minTTL uint8, maxTTL uint8, delay time.Duration, timeout time.Duration, useDriver bool) *UDPv4 {
	icmpParser := icmp.NewICMPUDPParser()
	buffer := gopacket.NewSerializeBufferExpectedSize(36, 0)

	return &UDPv4{
		Target:           target,
		TargetPort:       targetPort,
		MinTTL:           minTTL,
		MaxTTL:           maxTTL,
		srcIP:            net.IP{}, // avoid linter error on linux as it's only used on windows
		srcPort:          0,        // avoid linter error on linux as it's only used on windows
		Delay:            delay,
		Timeout:          timeout,
		icmpParser:       icmpParser,
		buffer:           buffer,
		UseWindowsDriver: useDriver,
	}
}

const magic = "NSMNC"
const magicLen = uint16(len(magic))

func repeatMagic(packetLen uint16) []byte {
	udpPayload := bytes.Repeat([]byte(magic), int(packetLen/magicLen)+1)[:packetLen]
	return udpPayload
}

// createRawUDPBuffer creates a raw UDP packet with the specified parameters
func (u *UDPv4) createRawUDPBuffer(sourceIP net.IP, sourcePort uint16, destIP net.IP, destPort uint16, ttl uint8) (uint16, []byte, uint16, error) { //nolint:unused
	// if this function is modified in a way that changes the size,
	// update the NewSerializeBufferExpectedSize call in NewUDPv4
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(sourcePort),
		DstPort: layers.UDPPort(destPort),
	}
	var id uint16

	// TODO: compute checksum before serialization so we
	// can set ID field of the IP header to detect NATs just
	// as is done in dublin-traceroute. Gopacket doesn't expose
	// the checksum computations and modifying the IP header after
	// serialization would change its checksum
	var ipLayer gopacket.SerializableLayer
	var payload gopacket.Payload
	if destIP.To4() != nil {
		ipv4Layer := &layers.IPv4{
			Version:  4,
			Length:   20,
			TTL:      ttl,
			Id:       41821 + uint16(ttl),
			Protocol: layers.IPProtocolUDP, // hard code UDP so other OSs can use it
			DstIP:    destIP,
			SrcIP:    sourceIP,
			Flags:    layers.IPv4DontFragment, // needed for dublin-traceroute-like NAT detection
		}
		err := udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
		if err != nil {
			return 0, nil, 0, fmt.Errorf("failed to create packet checksum: %w", err)
		}
		ipLayer = ipv4Layer

		id = ipv4Layer.Id
		udpPayload := []byte("NSMNC\x00\x00\x00")
		udpPayload[6] = byte((id >> 8) & 0xff)
		udpPayload[7] = byte(id & 0xff)
		payload = gopacket.Payload(udpPayload)
	} else {
		// Create IPv6 header
		ipv6Layer := &layers.IPv6{
			Version:    6,
			HopLimit:   uint8(ttl),
			NextHeader: layers.IPProtocolUDP,
			SrcIP:      sourceIP,
			DstIP:      destIP,
		}
		err := udpLayer.SetNetworkLayerForChecksum(ipv6Layer)
		if err != nil {
			return 0, nil, 0, fmt.Errorf("failed to create packet checksum: %w", err)
		}
		ipLayer = ipv6Layer

		packetLen := uint16(len(magic)) + uint16(ttl)
		payload = gopacket.Payload(repeatMagic(packetLen))
		const udpHeaderSize = 8
		id = packetLen + udpHeaderSize
	}
	// clear the gopacket.SerializeBuffer
	if len(u.buffer.Bytes()) > 0 {
		if err := u.buffer.Clear(); err != nil {
			u.buffer = gopacket.NewSerializeBuffer()
		}
	}
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(u.buffer, opts,
		ipLayer,
		udpLayer,
		payload,
	)
	if err != nil {
		return 0, nil, 0, fmt.Errorf("failed to serialize packet: %w", err)
	}

	packet := u.buffer.Bytes()
	return id, packet, udpLayer.Checksum, nil
}
