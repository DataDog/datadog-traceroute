// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build test && !windows && root

package packets

import (
	"bufio"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/testutils"
)

func newTestSource(t *testing.T) Source {
	t.Helper()
	handle, err := NewSourceSink(netip.MustParseAddr("127.0.0.1"), false)
	require.NoError(t, err)
	t.Cleanup(func() {
		handle.Source.Close()
		handle.Sink.Close()
	})
	return handle.Source
}

func doTCPExchange(t *testing.T) {
	t.Helper()
	server := testutils.NewTCPServerOnAddress("127.0.0.1:0", func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Write([]byte("pong\n"))
		testutils.GracefulCloseTCP(c)
	})
	t.Cleanup(server.Shutdown)
	require.NoError(t, server.Listen())
	server.StartAccepting()

	conn, err := net.Dial("tcp", server.Address())
	require.NoError(t, err)
	conn.Write([]byte("ping\n"))
	r := bufio.NewReader(conn)
	r.ReadBytes(byte('\n'))
	testutils.GracefulCloseTCP(conn)
}

func TestFilterICMPBlocksTCP(t *testing.T) {
	source := newTestSource(t)

	err := source.SetPacketFilter(PacketFilterSpec{FilterType: FilterTypeICMP})
	require.NoError(t, err)

	doTCPExchange(t)

	buf := make([]byte, 4096)
	source.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = source.Read(buf)

	var noPkt *common.ReceiveProbeNoPktError
	assert.ErrorAs(t, err, &noPkt,
		"expected timeout (TCP should be filtered by ICMP filter), got: %v", err)
}

func TestFilterICMPPassesICMP(t *testing.T) {
	source := newTestSource(t)

	err := source.SetPacketFilter(PacketFilterSpec{FilterType: FilterTypeICMP})
	require.NoError(t, err)

	// Send UDP to a closed port to trigger ICMP Port Unreachable
	conn, err := net.Dial("udp", "127.0.0.1:19234")
	require.NoError(t, err)
	conn.Write([]byte("hello"))
	conn.Close()

	buf := make([]byte, 4096)
	parser := NewFrameParser()
	source.SetReadDeadline(time.Now().Add(2 * time.Second))
	err = ReadAndParse(source, buf, parser)
	require.NoError(t, err, "expected to capture ICMP packet")
	assert.Equal(t, layers.LayerTypeICMPv4, parser.GetTransportLayer())
}
