// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package icmpecho

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/packets"
	"github.com/DataDog/datadog-traceroute/result"
)

// Traceroute runs an ICMP Echo traceroute
func (i *ICMPv4) Traceroute() (*result.TracerouteRun, error) {
	targetAddr, ok := common.UnmappedAddrFromSlice(i.Target)
	if !ok {
		return nil, fmt.Errorf("failed to get netipAddr for target %s", i.Target)
	}
	i.Target = targetAddr.AsSlice()

	addr, conn, err := common.LocalAddrForHost(i.Target, 33434) // Use a dummy port for local address discovery
	if err != nil {
		return nil, fmt.Errorf("ICMP Traceroute failed to get local address for target: %w", err)
	}
	defer conn.Close()
	i.srcIP = addr.IP

	// Initialize identifier and sequence base with random values
	i.identifier = uint16(rand.Uint32())
	i.seqBase = uint16(rand.Uint32())

	// get this platform's Source and Sink implementations
	handle, err := packets.NewSourceSink(targetAddr, i.UseWindowsDriver)
	if err != nil {
		return nil, fmt.Errorf("ICMP Traceroute failed to make NewSourceSink: %w", err)
	}
	if handle.MustClosePort {
		conn.Close()
	}

	// Set packet filter to only receive ICMP packets
	err = handle.Source.SetPacketFilter(packets.PacketFilterSpec{
		FilterType: packets.FilterTypeICMP,
	})
	if err != nil {
		handle.Source.Close()
		handle.Sink.Close()
		return nil, fmt.Errorf("ICMP traceroute failed to set packet filter: %w", err)
	}

	driver := newICMPDriver(i, handle.Sink, handle.Source)
	defer driver.Close()

	params := common.TracerouteParallelParams{
		TracerouteParams: common.TracerouteParams{
			MinTTL:            i.MinTTL,
			MaxTTL:            i.MaxTTL,
			TracerouteTimeout: i.Timeout,
			PollFrequency:     100 * time.Millisecond,
			SendDelay:         i.Delay,
		},
	}
	resp, err := common.TracerouteParallel(context.Background(), driver, params)
	if err != nil {
		return nil, err
	}

	hops, err := common.ToHops(params.TracerouteParams, resp)
	if err != nil {
		return nil, fmt.Errorf("ICMP traceroute ToHops failed: %w", err)
	}

	trRun := &result.TracerouteRun{
		Source: result.TracerouteSource{
			IPAddress: i.srcIP,
			Port:      0, // ICMP doesn't use ports
		},
		Destination: result.TracerouteDestination{
			IPAddress: i.Target,
			Port:      0, // ICMP doesn't use ports
		},
		Hops: hops,
	}

	return trRun, nil
}
