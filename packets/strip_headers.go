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

func stripIPv6Header(buf []byte) ([]byte, uint8, error) {
	var ip6 layers.IPv6
	err := (&ip6).DecodeFromBytes(buf, gopacket.NilDecodeFeedback)
	if err != nil {
		return nil, 0, fmt.Errorf("stripIPv6Header failed to decode IPv6: %w", err)
	}
	return ip6.Payload, ip6.HopLimit, nil
}
