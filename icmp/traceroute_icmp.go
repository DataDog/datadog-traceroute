// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

// Package icmp has icmp tracerouting logic
package icmp

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/log"
	"github.com/DataDog/datadog-traceroute/packets"
	"github.com/DataDog/datadog-traceroute/result"
)

// Params is the ICMP traceroute parameters
type Params struct {
	// Target is the IP:port to traceroute
	Target    netip.Addr
	RawTarget string
	// ParallelParams are the standard params for parallel traceroutes
	ParallelParams common.TracerouteParallelParams
}

// MaxTimeout returns the sum of all timeouts/delays for an ICMP traceroute
func (p Params) MaxTimeout() time.Duration {
	ttl := time.Duration(p.ParallelParams.MaxTTL - p.ParallelParams.MinTTL)
	return ttl * p.ParallelParams.MaxTimeout()
}

func (p Params) validate() error {
	addr := p.Target
	if !addr.IsValid() {
		return fmt.Errorf("ICMP traceroute provided invalid IP address")
	}
	return nil
}

type icmpResult struct {
	LocalAddr netip.AddrPort
	Hops      []*common.ProbeResponse
}

func doRunICMPTracerouteOnce(ctx context.Context, p Params) (*icmpResult, error) {
	err := p.validate()
	if err != nil {
		return nil, fmt.Errorf("invalid icmp driver params: %w", err)
	}

	target, err := parseTarget(p.RawTarget, 80, false)
	if err != nil {
		return nil, fmt.Errorf("parseTarget: %w", err)
	}
	p.Target = target.Addr()

	local, udpConn, err := common.LocalAddrForHost(p.Target.AsSlice(), 80)
	if err != nil {
		return nil, fmt.Errorf("failed to get local addr: %w", err)
	}
	udpConn.Close()
	deadline := time.Now().Add(p.MaxTimeout())
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	// get this platform's TracerouteSource and Sink implementations
	handle, err := packets.NewSourceSink(p.Target)
	if err != nil {
		return nil, fmt.Errorf("ICMP Traceroute failed to make NewSourceSink: %w", err)
	}
	err = handle.Source.SetPacketFilter(packets.PacketFilterSpec{
		FilterType: packets.FilterTypeICMP,
	})
	if err != nil {
		return nil, fmt.Errorf("ICMP traceroute failed to set packet filter: %w", err)
	}

	fmt.Println("local.AddrPort().Addr()", local.AddrPort().Addr())
	// create the raw packet connection which watches for TCP/ICMP responses
	driver := newICMPDriver(p, local.AddrPort().Addr(), handle.Sink, handle.Source)
	defer driver.Close()

	log.Debugf("icmp traceroute dialing %s", p.Target)
	// this actually runs the traceroute
	resp, err := common.TracerouteParallel(ctx, driver, p.ParallelParams)
	if err != nil {
		return nil, fmt.Errorf("icmp traceroute failed: %w", err)
	}

	result := &icmpResult{
		LocalAddr: local.AddrPort(),
		Hops:      resp,
	}
	return result, nil
}

func parseTarget(raw string, defaultPort int, wantIPv6 bool) (netip.AddrPort, error) {
	var host, portStr string
	var err error

	if !hasPort(raw) {
		portStr = strconv.Itoa(defaultPort)
		unwrappedHost := strings.Trim(raw, "[]")
		raw = net.JoinHostPort(unwrappedHost, portStr)
	}

	host, portStr, err = net.SplitHostPort(raw)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid address: %w", err)
	}

	ip, err := netip.ParseAddr(host)
	if err != nil {
		// Not an IP — do DNS resolution
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return netip.AddrPort{}, fmt.Errorf("failed to resolve host %q: %w", host, err)
		}

		fmt.Println("ips", ips)
		// shuffle
		for i := range ips {
			j := rand.Intn(i + 1)
			ips[i], ips[j] = ips[j], ips[i]
		}
		fmt.Println("ips", ips)

		found := false
		for _, r := range ips {
			if wantIPv6 {
				if r.To16() != nil {
					ip = netip.MustParseAddr(r.String())
					found = true
					break
				}
			} else {
				if r.To4() != nil {
					ip = netip.MustParseAddr(r.String())
					found = true
					break
				}
			}
		}
		if !found {
			return netip.AddrPort{}, fmt.Errorf("failed to resolve host %q: %w", host, err)
		}
		if !ip.IsValid() {
			ip = netip.MustParseAddr(ips[0].String())
		}
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return netip.AddrPort{}, fmt.Errorf("invalid port: %v", portStr)
	}
	fmt.Println("ip", ip)

	return netip.AddrPortFrom(ip, uint16(port)), nil
}

// hasPort returns true if the input string includes a port
func hasPort(s string) bool {
	if strings.HasPrefix(s, "[") {
		return strings.Contains(s, "]:")
	}
	return strings.Count(s, ":") == 1
}

// RunICMPTraceroute fully executes a ICMP traceroute using the given parameters
func RunICMPTraceroute(ctx context.Context, p Params) (*result.Results, error) {
	var runs []result.TracerouteRun
	for i := 0; i < 3; i++ {
		tracerouteRun, err := runICMPTracerouteOnce(ctx, p)
		if err != nil {
			return nil, err
		}
		runs = append(runs, tracerouteRun)
	}

	res := &result.Results{
		Traceroute: result.Traceroute{
			Runs: runs,
		},
		Tags: []string{"icmp"},
	}

	return res, nil
}

func runICMPTracerouteOnce(ctx context.Context, p Params) (result.TracerouteRun, error) {
	icmpResult, err := doRunICMPTracerouteOnce(ctx, p)
	if err != nil {
		return result.TracerouteRun{}, fmt.Errorf("icmp traceroute failed: %w", err)
	}

	hops, err := common.ToHops(p.ParallelParams.TracerouteParams, icmpResult.Hops)
	if err != nil {
		return result.TracerouteRun{}, fmt.Errorf("icmp traceroute ToHops failed: %w", err)
	}

	tracerouteRun := result.TracerouteRun{
		Source: result.TracerouteSource{
			IP:   icmpResult.LocalAddr.Addr().AsSlice(),
			Port: icmpResult.LocalAddr.Port(),
		},
		Destination: result.TracerouteDestination{
			IP: p.Target.String(),
		},
		Hops: hops,
	}
	return tracerouteRun, nil
}
