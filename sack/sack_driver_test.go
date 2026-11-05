// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package sack

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/packets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type handshakeTestSource struct {
	deadline time.Time
	read     func([]byte) (int, error)
}

func (s *handshakeTestSource) SetReadDeadline(deadline time.Time) error {
	s.deadline = deadline
	return nil
}

func (s *handshakeTestSource) Read(buffer []byte) (int, error) {
	return s.read(buffer)
}

func (*handshakeTestSource) Close() error {
	return nil
}

func (*handshakeTestSource) SetPacketFilter(packets.PacketFilterSpec) error {
	return nil
}

func newHandshakeTestDriver(source packets.Source) *sackDriver {
	return &sackDriver{
		source: source,
		buffer: make([]byte, 1024),
		parser: packets.NewFrameParser(),
	}
}

func TestReadHandshakeClampsReadDeadlineToContext(t *testing.T) {
	ctxDeadline := time.Now().Add(20 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), ctxDeadline)
	defer cancel()

	source := &handshakeTestSource{
		read: func([]byte) (int, error) {
			return 0, os.ErrDeadlineExceeded
		},
	}

	err := newHandshakeTestDriver(source).ReadHandshake(ctx, 1234)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Equal(t, ctxDeadline, source.deadline)
}

func TestReadHandshakeClassifiesInternalReadDeadlineAsTimeout(t *testing.T) {
	source := &handshakeTestSource{
		read: func([]byte) (int, error) {
			time.Sleep(20 * time.Millisecond)
			return 0, os.ErrDeadlineExceeded
		},
	}

	err := newHandshakeTestDriver(source).readHandshake(context.Background(), 1234, 20*time.Millisecond)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestReadHandshakePollsForDeadlineFreeCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	source := &handshakeTestSource{}
	source.read = func([]byte) (int, error) {
		cancel()
		time.Sleep(time.Until(source.deadline))
		return 0, os.ErrDeadlineExceeded
	}

	start := time.Now()
	err := newHandshakeTestDriver(source).ReadHandshake(ctx, 1234)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.WithinDuration(t, start.Add(common.DefaultProbePollFrequency), source.deadline, 20*time.Millisecond)
	assert.Less(t, time.Since(start), sackHandshakeTimeout)
}

func TestReadHandshakeReturnsContextDeadlineExceededWhenContextExpiresDuringRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	source := &handshakeTestSource{
		read: func([]byte) (int, error) {
			<-ctx.Done()
			return 0, os.ErrDeadlineExceeded
		},
	}

	err := newHandshakeTestDriver(source).ReadHandshake(ctx, 1234)

	require.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded))
	ctxDeadline, ok := ctx.Deadline()
	require.True(t, ok)
	assert.Equal(t, ctxDeadline, source.deadline)
}
