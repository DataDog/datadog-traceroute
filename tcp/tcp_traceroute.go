// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package tcp

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/packets"
	"github.com/DataDog/datadog-traceroute/result"
)

// Traceroute runs a TCP traceroute
func (t *TCPv4) Traceroute() (*result.Results, error) {
	addr, conn, err := common.LocalAddrForHost(t.Target, t.DestPort)
	if err != nil {
		return nil, fmt.Errorf("TCP Traceroute failed to get local address for target: %w", err)
	}
	conn.Close() // we don't need the UDP port here
	t.srcIP = addr.IP
	localAddr, ok := common.UnmappedAddrFromSlice(t.srcIP)
	if !ok {
		return nil, fmt.Errorf("failed to get netipAddr for source %s", t.srcIP)
	}

	// reserve a local port so that the tcpDriver has free reign to safely send packets on it
	port, tcpListener, err := reserveLocalPort()
	if err != nil {
		return nil, fmt.Errorf("TCP Traceroute failed to create TCP listener: %w", err)
	}

	defer tcpListener.Close()
	t.srcPort = port

	targetAddr, ok := common.UnmappedAddrFromSlice(t.Target)
	if !ok {
		return nil, fmt.Errorf("failed to get netipAddr for target %s", t.Target)
	}

	// get this platform's Source and Sink implementations
	handle, err := packets.NewSourceSink(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("TCP Traceroute failed to make NewSourceSink: %w", err)
	}
	if handle.MustClosePort {
		tcpListener.Close()
	}
	err = handle.Source.SetPacketFilter(packets.PacketFilterSpec{
		FilterType: packets.FilterTypeTCP,
		FilterConfig: packets.FilterConfig{
			Src: netip.AddrPortFrom(targetAddr, t.DestPort),
			Dst: netip.AddrPortFrom(localAddr, port),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("UDP traceroute failed to set packet filter: %w", err)
	}

	driver := newTCPDriver(t, handle.Sink, handle.Source)
	defer driver.Close()

	params := common.TracerouteSerialParams{
		TracerouteParams: common.TracerouteParams{
			MinTTL:            t.MinTTL,
			MaxTTL:            t.MaxTTL,
			TracerouteTimeout: t.Timeout,
			PollFrequency:     100 * time.Millisecond,
			SendDelay:         t.Delay,
		},
	}
	resp, err := common.TracerouteSerial(context.Background(), driver, params)
	if err != nil {
		return nil, err
	}

	hops, err := common.ToHops(params.TracerouteParams, resp)
	if err != nil {
		return nil, fmt.Errorf("SYN traceroute ToHops failed: %w", err)
	}

	result := &result.Results{
		Traceroute: result.Traceroute{
			Runs: []result.TracerouteRun{
				{
					Source: result.TracerouteSource{
						IpAddress: t.srcIP,
						Port:      t.srcPort,
					},
					Destination: result.TracerouteDestination{
						IpAddress: t.Target,
						Port:      t.DestPort,
					},
					Hops: hops,
				},
			},
		},
	}

	return result, nil
}
