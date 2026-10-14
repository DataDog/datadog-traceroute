// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package sack

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/packets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type blockingHandshakeSource struct {
	ctx     context.Context
	started chan struct{}
	once    sync.Once
}

func (*blockingHandshakeSource) SetReadDeadline(time.Time) error {
	return nil
}

func (s *blockingHandshakeSource) Read([]byte) (int, error) {
	s.once.Do(func() { close(s.started) })
	<-s.ctx.Done()
	return 0, os.ErrDeadlineExceeded
}

func (*blockingHandshakeSource) Close() error {
	return nil
}

func (*blockingHandshakeSource) SetPacketFilter(packets.PacketFilterSpec) error {
	return nil
}

type noopSink struct{}

func (noopSink) WriteTo([]byte, netip.AddrPort) error {
	return nil
}

func (noopSink) Close() error {
	return nil
}

func newSACKTimeoutTestParams(t *testing.T) (Params, func()) {
	t.Helper()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)

	serverDone := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		<-serverDone
	}()

	target, err := netip.ParseAddrPort(listener.Addr().String())
	require.NoError(t, err)
	params := Params{
		Target:           target,
		HandshakeTimeout: time.Second,
		ParallelParams: common.TracerouteParallelParams{
			TracerouteParams: common.TracerouteParams{
				MinTTL:            1,
				MaxTTL:            2,
				TracerouteTimeout: time.Second,
				PollFrequency:     10 * time.Millisecond,
				SendDelay:         10 * time.Millisecond,
			},
		},
	}
	cleanup := func() {
		close(serverDone)
		_ = listener.Close()
	}
	return params, cleanup
}

func TestRunSackTracerouteContextBoundsBlockedHandshake(t *testing.T) {
	// The Linux fake-network endpoint does not reliably support SACK, so keep the
	// TotalTimeout contract deterministic here by blocking the real handshake path
	// and verifying that its caller context bounds the complete SACK runner.
	originalNewSourceSink := newSourceSink
	defer func() { newSourceSink = originalNewSourceSink }()

	t.Run("deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		started := make(chan struct{})
		newSourceSink = func(netip.Addr, bool) (packets.SourceSinkHandle, error) {
			return packets.SourceSinkHandle{
				Source: &blockingHandshakeSource{ctx: ctx, started: started},
				Sink:   noopSink{},
			}, nil
		}
		params, cleanup := newSACKTimeoutTestParams(t)
		defer cleanup()

		start := time.Now()
		results, err := RunSackTraceroute(ctx, params)
		elapsed := time.Since(start)

		require.Error(t, err)
		assert.True(t, errors.Is(err, context.DeadlineExceeded), "expected wrapped context deadline, got %v", err)
		assert.Nil(t, results)
		assert.Less(t, elapsed, 500*time.Millisecond)
		select {
		case <-started:
		default:
			t.Fatal("complete SACK runner did not reach the blocked handshake")
		}
	})

	t.Run("explicit cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		started := make(chan struct{})
		newSourceSink = func(netip.Addr, bool) (packets.SourceSinkHandle, error) {
			return packets.SourceSinkHandle{
				Source: &blockingHandshakeSource{ctx: ctx, started: started},
				Sink:   noopSink{},
			}, nil
		}
		params, cleanup := newSACKTimeoutTestParams(t)
		defer cleanup()

		go func() {
			<-started
			cancel()
		}()

		start := time.Now()
		results, err := RunSackTraceroute(ctx, params)
		elapsed := time.Since(start)

		require.Error(t, err)
		assert.True(t, errors.Is(err, context.Canceled), "expected wrapped context cancellation, got %v", err)
		assert.Nil(t, results)
		assert.Less(t, elapsed, 500*time.Millisecond)
	})
}
