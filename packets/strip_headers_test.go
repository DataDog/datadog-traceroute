package packets

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestStripLinkLayerHeader(t *testing.T) {
	// Build a simple raw IPv4 packet.
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.IPv4(192, 0, 2, 1),
		DstIP:    net.IPv4(192, 0, 2, 2),
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: 123,
		DstPort: 456,
	}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip4))

	rawBuf := gopacket.NewSerializeBuffer()
	rawOpts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	require.NoError(t, gopacket.SerializeLayers(rawBuf, rawOpts, ip4, udp, gopacket.Payload("hello")))
	raw := rawBuf.Bytes()

	t.Run("raw IP", func(t *testing.T) {
		got, err := stripLinkLayerHeader(raw)
		require.NoError(t, err)
		require.Equal(t, raw, got)
	})

	t.Run("ethernet header", func(t *testing.T) {
		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 1},
			DstMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 2},
			EthernetType: layers.EthernetTypeIPv4,
		}
		buf := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, eth, gopacket.Payload(raw)))

		got, err := stripLinkLayerHeader(buf.Bytes())
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(got), len(raw))
		require.Equal(t, raw, got[:len(raw)])
	})

	t.Run("linux cooked capture (SLL)", func(t *testing.T) {
		// 16-byte Linux cooked capture header (SLL):
		// uint16 pkttype, uint16 hatype, uint16 halen, uint8 addr[8], uint16 protocol.
		sllHeader := make([]byte, 16)
		binary.BigEndian.PutUint16(sllHeader[14:16], uint16(layers.EthernetTypeIPv4))
		packet := append(sllHeader, raw...)

		got, err := stripLinkLayerHeader(packet)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(got), len(raw))
		require.Equal(t, raw, got[:len(raw)])
	})

	t.Run("non-IP packet", func(t *testing.T) {
		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 1},
			DstMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 2},
			EthernetType: layers.EthernetTypeARP,
		}
		buf := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, eth, gopacket.Payload("arp")))

		got, err := stripLinkLayerHeader(buf.Bytes())
		require.NoError(t, err)
		require.Nil(t, got)
	})
}
