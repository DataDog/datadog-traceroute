// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package tcp adds a TCP traceroute implementation to the agent
package tcp

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/log"
	"github.com/DataDog/datadog-traceroute/result"
	"github.com/DataDog/datadog-traceroute/winconn"
)

// TracerouteSequentialSocket runs a traceroute sequentially where a packet is
// sent and we wait for a response before sending the next packet. This method
// uses socket options to set the TTL and get the hop IP. It has no deadline of
// its own; prefer TracerouteSequentialSocketContext when the caller wants the
// run bounded by a context deadline.
func (t *TCPv4) TracerouteSequentialSocket() (*result.TracerouteRun, error) {
	return t.TracerouteSequentialSocketContext(context.Background())
}

// TracerouteSequentialSocketContext is the context-aware variant of TracerouteSequentialSocket.
func (t *TCPv4) TracerouteSequentialSocketContext(ctx context.Context) (*result.TracerouteRun, error) {
	log.Debugf("Running traceroute to %+v", t)
	// Get local address for the interface that connects to this
	// host and store in the probe
	addr, conn, err := common.LocalAddrForHost(t.Target, t.DestPort)
	if err != nil {
		return nil, fmt.Errorf("failed to get local address for target: %w", err)
	}
	defer conn.Close()
	t.srcIP = addr.IP
	t.srcPort = addr.AddrPort().Port()

	hops := make([]*result.TracerouteHop, 0, int(t.MaxTTL-t.MinTTL)+1)

	for i := int(t.MinTTL); i <= int(t.MaxTTL); i++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		// Cap this hop's timeout by the context's remaining deadline so a single
		// hop can't block past the overall deadline (e.g. TotalTimeout).
		hopTimeout, err := capHopTimeout(ctx, t.Timeout)
		if err != nil {
			return nil, err
		}

		s, err := winconn.NewConn()
		if err != nil {
			return nil, fmt.Errorf("failed to create raw socket: %w", err)
		}
		hop, err := t.sendAndReceiveSocket(s, i, hopTimeout)
		s.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to run traceroute: %w", err)
		}
		hops = append(hops, hop)
		log.Tracef("Discovered hop: %+v", hop)
		// if we've reached our destination,
		// we're done
		if hop.IsDest {
			break
		}
	}

	return &result.TracerouteRun{
		Source: result.TracerouteSource{
			IPAddress: t.srcIP,
			Port:      t.srcPort,
		},
		Destination: result.TracerouteDestination{
			IPAddress: t.Target,
			Port:      t.DestPort,
		},
		Hops: hops,
	}, nil
}

// capHopTimeout returns baseTimeout, unless ctx has a deadline that would elapse sooner,
// in which case it returns the time remaining until that deadline instead. This keeps a
// single hop's GetHop call from blocking past an overall deadline such as TotalTimeout.
// An already-expired deadline returns context.DeadlineExceeded.
func capHopTimeout(ctx context.Context, baseTimeout time.Duration) (time.Duration, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return baseTimeout, nil
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0, context.DeadlineExceeded
	}
	if baseTimeout <= 0 {
		return remaining, nil
	}
	if remaining < baseTimeout {
		return remaining, nil
	}
	return baseTimeout, nil
}

func (t *TCPv4) sendAndReceiveSocket(s winconn.ConnWrapper, ttl int, timeout time.Duration) (*result.TracerouteHop, error) {
	// set the TTL
	err := s.SetTTL(ttl)
	if err != nil {
		return nil, fmt.Errorf("failed to set TTL: %w", err)
	}

	start := time.Now() // TODO: is this the best place to start?
	hopIP, end, icmpType, icmpCode, err := s.GetHop(timeout, t.Target, t.DestPort)
	if err != nil {
		log.Errorf("failed to get hop: %s", err.Error())
		return nil, fmt.Errorf("failed to get hop: %w", err)
	}

	rtt := time.Duration(0)
	if !hopIP.Equal(net.IP{}) {
		rtt = end.Sub(start)
	}

	return &result.TracerouteHop{
		IPAddress: hopIP,
		Port:      0, // TODO: fix this
		ICMPType:  icmpType,
		ICMPCode:  icmpCode,
		RTT:       common.ConvertDurationToMs(rtt),
		IsDest:    hopIP.Equal(t.Target),
	}, nil
}
