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

// stripEthernetHeader removes the preceding ethernet header from the buffer
// and returns the IP payload. It also handles raw IP packets (without Ethernet
// headers) which can occur on tunnel interfaces like WireGuard.
func stripEthernetHeader(buf []byte) ([]byte, error) {
	if len(buf) == 0 {
		return nil, fmt.Errorf("stripEthernetHeader: empty buffer")
	}

	// Check if this looks like a raw IP packet (no Ethernet header).
	// The first nibble of an IPv4 header is 0x4, and for IPv6 it's 0x6.
	// This can happen on tunnel interfaces like WireGuard.
	ipVersion := buf[0] >> 4
	if ipVersion == 4 || ipVersion == 6 {
		// It looks like an IP packet. However, we need to be careful because
		// an Ethernet frame might coincidentally have its first byte match
		// an IP version. Try to decode as Ethernet first.
		var eth layers.Ethernet
		err := (&eth).DecodeFromBytes(buf, gopacket.NilDecodeFeedback)
		if err != nil {
			// Failed to decode as Ethernet - this is a raw IP packet
			return buf, nil
		}

		// Successfully decoded as Ethernet. Now check if it's actually valid.
		// If it claims to be an IP packet, the payload should also start with
		// the same IP version. If not, we probably have a raw IP packet that
		// was misinterpreted as Ethernet.
		if eth.EthernetType == layers.EthernetTypeIPv4 || eth.EthernetType == layers.EthernetTypeIPv6 {
			if len(eth.Payload) > 0 {
				payloadIPVersion := eth.Payload[0] >> 4
				// For IPv4 Ethernet frame, payload should start with 0x4X
				// For IPv6 Ethernet frame, payload should start with 0x6X
				expectedVersion := uint8(4)
				if eth.EthernetType == layers.EthernetTypeIPv6 {
					expectedVersion = 6
				}
				if payloadIPVersion == expectedVersion {
					// This is a valid Ethernet frame with IP payload
					return eth.Payload, nil
				}
			}
			// The EtherType claims IP but the payload doesn't match
			// This is likely a raw IP packet misinterpreted as Ethernet
			return buf, nil
		}
		// EtherType is not IP - this is either a non-IP Ethernet frame
		// or a raw IP packet. Check if it's plausibly a raw IP packet.
		if ipVersion == 4 || ipVersion == 6 {
			return buf, nil
		}
		return nil, nil
	}

	// Doesn't start with IP version nibble, try to decode as Ethernet
	var eth layers.Ethernet
	err := (&eth).DecodeFromBytes(buf, gopacket.NilDecodeFeedback)
	if err != nil {
		return nil, fmt.Errorf("stripEthernetHeader failed to decode ethernet: %w", err)
	}
	// return zero bytes when it's not an IP packet
	if eth.EthernetType != layers.EthernetTypeIPv4 && eth.EthernetType != layers.EthernetTypeIPv6 {
		return nil, nil
	}
	return eth.Payload, nil
}

func stripIPv6Header(buf []byte) ([]byte, uint8, error) {
	var ip6 layers.IPv6
	err := (&ip6).DecodeFromBytes(buf, gopacket.NilDecodeFeedback)
	if err != nil {
		return nil, 0, fmt.Errorf("stripIPv6Header failed to decode IPv6: %w", err)
	}
	return ip6.Payload, ip6.HopLimit, nil
}
