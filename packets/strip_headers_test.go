// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package packets

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestStripEthernetHeader(t *testing.T) {
	t.Run("empty buffer", func(t *testing.T) {
		_, err := stripEthernetHeader(nil)
		require.Error(t, err)
	})

	t.Run("ethernet frame with IPv4", func(t *testing.T) {
		// Create a simple Ethernet + IPv4 packet
		eth := layers.Ethernet{
			SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			DstMAC:       []byte{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := layers.IPv4{
			Version:  4,
			IHL:      5,
			SrcIP:    []byte{192, 168, 1, 1},
			DstIP:    []byte{192, 168, 1, 2},
			Protocol: layers.IPProtocolICMPv4,
		}

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true}
		err := gopacket.SerializeLayers(buf, opts, &eth, &ip)
		require.NoError(t, err)

		payload, err := stripEthernetHeader(buf.Bytes())
		require.NoError(t, err)
		require.NotNil(t, payload)
		// Payload should start with IPv4 version nibble (4)
		require.Equal(t, uint8(4), payload[0]>>4)
	})

	t.Run("raw IPv4 packet without ethernet header", func(t *testing.T) {
		// Create a raw IPv4 packet (like what WireGuard interfaces might provide)
		ip := layers.IPv4{
			Version:  4,
			IHL:      5,
			SrcIP:    []byte{10, 8, 0, 1},
			DstIP:    []byte{10, 8, 0, 2},
			Protocol: layers.IPProtocolICMPv4,
		}

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true}
		err := gopacket.SerializeLayers(buf, opts, &ip)
		require.NoError(t, err)

		payload, err := stripEthernetHeader(buf.Bytes())
		require.NoError(t, err)
		require.NotNil(t, payload)
		// For raw IP packets, the payload should be the same as the input
		require.Equal(t, buf.Bytes(), payload)
	})

	t.Run("raw IPv6 packet without ethernet header", func(t *testing.T) {
		// Create a raw IPv6 packet (like what WireGuard interfaces might provide)
		ip6 := layers.IPv6{
			Version:    6,
			SrcIP:      []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			DstIP:      []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
			NextHeader: layers.IPProtocolICMPv6,
		}

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true}
		err := gopacket.SerializeLayers(buf, opts, &ip6)
		require.NoError(t, err)

		payload, err := stripEthernetHeader(buf.Bytes())
		require.NoError(t, err)
		require.NotNil(t, payload)
		// For raw IP packets, the payload should be the same as the input
		require.Equal(t, buf.Bytes(), payload)
	})

	t.Run("ethernet frame with non-IP protocol", func(t *testing.T) {
		// Create an Ethernet frame with ARP
		eth := layers.Ethernet{
			SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			DstMAC:       []byte{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
			EthernetType: layers.EthernetTypeARP,
		}
		arp := layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			SourceProtAddress: []byte{192, 168, 1, 1},
			DstHwAddress:      []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			DstProtAddress:    []byte{192, 168, 1, 2},
		}

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true}
		err := gopacket.SerializeLayers(buf, opts, &eth, &arp)
		require.NoError(t, err)

		payload, err := stripEthernetHeader(buf.Bytes())
		require.NoError(t, err)
		// For non-IP protocols, payload should be nil
		require.Nil(t, payload)
	})
}
