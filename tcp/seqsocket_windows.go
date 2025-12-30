// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package tcp adds a TCP traceroute implementation to the agent
package tcp

import (
	"fmt"
	"net"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/localaddr"
	"github.com/DataDog/datadog-traceroute/log"
	"github.com/DataDog/datadog-traceroute/result"
	"github.com/DataDog/datadog-traceroute/winconn"
)

// TracerouteSequentialSocket runs a traceroute sequentially where a packet is
// sent and we wait for a response before sending the next packet
// This method uses socket options to set the TTL and get the hop IP
func (t *TCPv4) TracerouteSequentialSocket() (*result.TracerouteRun, error) {
	log.Debugf("Running traceroute to %+v", t)
	// Get local address for the interface that connects to this
	// host and store in the probe
	addr, conn, err := localaddr.LocalAddrForHost(t.Target, t.DestPort)
	if err != nil {
		return nil, fmt.Errorf("failed to get local address for target: %w", err)
	}
	defer conn.Close()
	t.srcIP = addr.IP
	t.srcPort = addr.AddrPort().Port()

	hops := make([]*result.TracerouteHop, 0, int(t.MaxTTL-t.MinTTL)+1)

	for i := int(t.MinTTL); i <= int(t.MaxTTL); i++ {
		s, err := winconn.NewConn()
		if err != nil {
			return nil, fmt.Errorf("failed to create raw socket: %w", err)
		}
		hop, err := t.sendAndReceiveSocket(s, i, t.Timeout)
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
