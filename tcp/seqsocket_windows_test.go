// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package tcp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/DataDog/datadog-traceroute/winconn"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
)

func TestSendAndReceiveSocketPassesContextAndTimeout(t *testing.T) {
	ctrl := gomock.NewController(t)
	socket := winconn.NewMockConnWrapper(ctrl)
	target := net.ParseIP("192.0.2.1")
	timeout := 3 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	socket.EXPECT().SetTTL(7).Return(nil)
	socket.EXPECT().GetHop(ctx, timeout, target, uint16(443)).
		Return(target, time.Now(), uint8(0), uint8(0), nil)

	traceroute := &TCPv4{
		Target:   target,
		DestPort: 443,
	}
	hop, err := traceroute.sendAndReceiveSocket(ctx, socket, 7, timeout)

	require.NoError(t, err)
	require.True(t, hop.IsDest)
}

func TestSendAndReceiveSocketHonorsContextDeadline(t *testing.T) {
	// The Windows syn-socket path has no Linux fake-network equivalent. Exercise its
	// native context boundary directly so a long per-probe timeout cannot hide the
	// shorter whole-run deadline.
	ctrl := gomock.NewController(t)
	socket := winconn.NewMockConnWrapper(ctrl)
	target := net.ParseIP("192.0.2.1")
	const totalTimeout = 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()

	socket.EXPECT().SetTTL(7).Return(nil)
	socket.EXPECT().GetHop(ctx, 3*time.Second, target, uint16(443)).
		DoAndReturn(func(ctx context.Context, _ time.Duration, _ net.IP, _ uint16) (net.IP, time.Time, uint8, uint8, error) {
			<-ctx.Done()
			return nil, time.Time{}, 0, 0, ctx.Err()
		})

	traceroute := &TCPv4{Target: target, DestPort: 443}
	start := time.Now()
	hop, err := traceroute.sendAndReceiveSocket(ctx, socket, 7, 3*time.Second)
	elapsed := time.Since(start)

	require.Nil(t, hop)
	require.True(t, errors.Is(err, context.DeadlineExceeded))
	require.Less(t, elapsed, 500*time.Millisecond)
}
