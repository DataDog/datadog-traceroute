// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package tcp adds a TCP traceroute implementation to the agent
package tcp

import (
	"net"
	"time"

	payload "github.com/AlexandreYang/datadog-traceroute/dublintraceroute/netpath_payload"
	"github.com/AlexandreYang/datadog-traceroute/dublintraceroute/utils"
)

type (
	// TCPv4 encapsulates the data needed to run
	// a TCPv4 traceroute
	TCPv4 struct {
		TargetHostname string
		TargetIP       net.IP
		srcIP          net.IP // calculated internally
		srcPort        uint16 // calculated internally
		DestPort       uint16
		NumPaths       uint16
		MinTTL         uint8
		MaxTTL         uint8
		Delay          time.Duration // delay between sending packets (not applicable if we go the serial send/receive route)
		Timeout        time.Duration // full timeout for all packets
	}
)

func (t *TCPv4) Validate() error {
	//TODO implement me
	//panic("implement me")
	return nil
}

func (t *TCPv4) Traceroute() (*payload.NetworkPath, error) {
	tcpRes, err := t.TracerouteSequential()
	if err != nil {
		return nil, err
	}

	traceroutePath := &payload.NetworkPath{
		//AgentVersion: version.AgentVersion,
		PathtraceID: payload.NewPathtraceID(),
		Protocol:    payload.ProtocolTCP,
		Timestamp:   time.Now().UnixMilli(),
		Source: payload.NetworkPathSource{
			Hostname: utils.GetHostname(),
			//NetworkID: r.networkID,
		},
		Destination: payload.NetworkPathDestination{
			Hostname:  t.TargetHostname,
			Port:      t.DestPort,
			IPAddress: t.TargetIP.String(),
		},
	}

	for idx, hop := range tcpRes.Hops {
		ttl := idx + 1
		isReachable := false
		if !hop.IP.Equal(net.IP{}) {
			isReachable = true
		}
		traceroutePath.Hops = append(traceroutePath.Hops, payload.NetworkPathHop{
			TTL:       ttl,
			IPAddress: hop.IP.String(),
			RTT:       float64(hop.RTT),
			Reachable: isReachable,
		})
	}

	return traceroutePath, nil
}

// Close doesn't to anything yet, but we should
// use this to close out long running sockets
// when we're done with a path test
func (t *TCPv4) Close() error {
	return nil
}
