// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package udp

import (
	"context"
	"fmt"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/packets"
	"github.com/DataDog/datadog-traceroute/result"
)

// Traceroute runs a UDP traceroute
func (u *UDPv4) Traceroute() (*result.Results, error) {
	targetAddr, ok := common.UnmappedAddrFromSlice(u.Target)
	if !ok {
		return nil, fmt.Errorf("failed to get netipAddr for target %s", u.Target)
	}
	u.Target = targetAddr.AsSlice()

	addr, conn, err := common.LocalAddrForHost(u.Target, u.TargetPort)
	if err != nil {
		return nil, fmt.Errorf("UDP Traceroute failed to get local address for target: %w", err)
	}
	defer conn.Close()
	u.srcIP = addr.IP
	u.srcPort = uint16(addr.Port)

	// get this platform's TracerouteSource and Sink implementations
	handle, err := packets.NewSourceSink(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("UDP Traceroute failed to make NewSourceSink: %w", err)
	}
	if handle.MustClosePort {
		conn.Close()
	}

	err = handle.Source.SetPacketFilter(packets.PacketFilterSpec{
		FilterType: packets.FilterTypeICMP,
	})
	if err != nil {
		return nil, fmt.Errorf("UDP traceroute failed to set packet filter: %w", err)
	}

	driver := newUDPDriver(u, handle.Sink, handle.Source)
	defer driver.Close()

	params := common.TracerouteParallelParams{
		TracerouteParams: common.TracerouteParams{
			MinTTL:            u.MinTTL,
			MaxTTL:            u.MaxTTL,
			TracerouteTimeout: u.Timeout,
			PollFrequency:     100 * time.Millisecond,
			SendDelay:         u.Delay,
		},
	}
	resp, err := common.TracerouteParallel(context.Background(), driver, params)
	if err != nil {
		return nil, err
	}

	hops, err := common.ToHops(params.TracerouteParams, resp)
	if err != nil {
		return nil, fmt.Errorf("UDP traceroute ToHops failed: %w", err)
	}

	result := &result.Results{
		Traceroute: result.Traceroute{
			Runs: []result.TracerouteRun{
				{
					Source: result.TracerouteSource{
						IP:   u.srcIP,
						Port: u.srcPort,
					},
					Destination: result.TracerouteDestination{
						IP:   u.Target,
						Port: u.TargetPort,
					},
					Hops: hops,
				},
			},
		},

		Tags: nil,
	}

	return result, nil
}
