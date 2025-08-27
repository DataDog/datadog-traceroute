// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package udp

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/packets"
)

// Traceroute runs a UDP traceroute
func (u *UDPv4) Traceroute() (*common.Results, error) {
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

	// get this platform's Source and Sink implementations
	handle, err := packets.NewSourceSink(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("UDP Traceroute failed to make NewSourceSink: %w", err)
	}
	if handle.MustClosePort {
		conn.Close()
	}

	// TODO remove localAddr once UDPv4 only uses AddrPort
	localAddr, _ := common.UnmappedAddrFromSlice(u.srcIP)
	err = handle.Source.SetPacketFilter(packets.PacketFilterSpec{
		FilterType: packets.FilterTypeUDP,
		FilterConfig: packets.FilterConfig{
			Src: netip.AddrPortFrom(targetAddr, u.TargetPort),
			Dst: netip.AddrPortFrom(localAddr, u.srcPort),
		},
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

	result := &common.Results{
		Source:     u.srcIP,
		SourcePort: u.srcPort,
		Target:     u.Target,
		DstPort:    u.TargetPort,
		Hops:       hops,
		Tags:       nil,
	}

	return result, nil
}
