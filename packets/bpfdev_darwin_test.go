// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build test && darwin && root

package packets

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestSourceForLoopback() (Source, func() error, error) {
	source, err := NewBpfDevice(netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		return nil, nil, err
	}
	return source, source.Close, nil
}

func TestPcapSourceDeliversPacketsWithoutReadTimeoutDelay(t *testing.T) {
	source, err := NewBpfDevice(netip.MustParseAddr("127.0.0.1"))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, source.Close())
	})

	require.NoError(t, source.SetPacketFilter(PacketFilterSpec{FilterType: FilterTypeSYNACK}))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = listener.Close()
	})

	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		acceptErr <- conn.Close()
	}()

	buf := make([]byte, 4096)
	parser := NewFrameParser()
	readResult := make(chan error, 1)
	start := time.Now()
	go func() {
		if err := source.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			readResult <- err
			return
		}
		readResult <- ReadAndParse(source, buf, parser)
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	select {
	case err := <-readResult:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for packet capture")
	}
	elapsed := time.Since(start)

	require.NoError(t, <-acceptErr)
	assert.Equal(t, layers.LayerTypeTCP, parser.GetTransportLayer())
	assert.True(t, parser.TCP.SYN)
	assert.True(t, parser.TCP.ACK)
	assert.Less(t, elapsed, 75*time.Millisecond, "pcap should deliver packets before the 100ms read timeout")
}
