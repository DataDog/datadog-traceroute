// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package packets

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// removes the preceding ethernet header from the buffer
func stripEthernetHeader(buf []byte) ([]byte, error) {
	var eth layers.Ethernet
	err := (&eth).DecodeFromBytes(buf, gopacket.NilDecodeFeedback)
	if err != nil {
		return nil, fmt.Errorf("stripEthernetHeader failed to decode ethernet: %w", err)
	}
	// return zero bytes when the it's not an IP packet
	if eth.EthernetType != layers.EthernetTypeIPv4 && eth.EthernetType != layers.EthernetTypeIPv6 {
		return nil, nil
	}
	return eth.Payload, nil
}

// stripLinkLayerHeader returns the payload starting at the IP header.
//
// AF_PACKET can yield different link-layer headers depending on the interface:
// - Ethernet devices: an Ethernet header precedes the IP packet.
// - Some L3 devices (e.g., WireGuard): the packet may begin directly with the IP header.
// - "Any"/cooked captures: Linux SLL/SLL2 headers may be used.
//
// For non-IP packets (or unsupported link headers), it returns (nil, nil) so callers can ignore
// the frame and continue reading.
func stripLinkLayerHeader(buf []byte) ([]byte, error) {
	if len(buf) < 1 {
		return nil, nil
	}

	// Raw IP packet (no link-layer header).
	switch buf[0] >> 4 {
	case 4, 6:
		return buf, nil
	}

	// Linux cooked capture (SLL). Only treat it as SLL if the embedded EtherType is IP.
	// Note: We can't just rely on DecodeFromBytes error to detect SLL because other link headers
	// (including Ethernet) may decode successfully but yield a non-IP EtherType.
	var sll layers.LinuxSLL
	if err := (&sll).DecodeFromBytes(buf, gopacket.NilDecodeFeedback); err == nil {
		if sll.EthernetType == layers.EthernetTypeIPv4 || sll.EthernetType == layers.EthernetTypeIPv6 {
			return sll.Payload, nil
		}
	}

	// Ethernet header.
	var eth layers.Ethernet
	if err := (&eth).DecodeFromBytes(buf, gopacket.NilDecodeFeedback); err == nil {
		if eth.EthernetType != layers.EthernetTypeIPv4 && eth.EthernetType != layers.EthernetTypeIPv6 {
			return nil, nil
		}
		return eth.Payload, nil
	}

	return nil, nil
}

func stripIPv6Header(buf []byte) ([]byte, uint8, error) {
	var ip6 layers.IPv6
	err := (&ip6).DecodeFromBytes(buf, gopacket.NilDecodeFeedback)
	if err != nil {
		return nil, 0, fmt.Errorf("stripIPv6Header failed to decode IPv6: %w", err)
	}
	return ip6.Payload, ip6.HopLimit, nil
}
