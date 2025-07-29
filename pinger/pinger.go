// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package pinger implements ICMP ping functionality for the agent
package pinger

import (
	"errors"
	"time"
)

const (
	DefaultCount      = 50
	DefaultIntervalMs = 20
	DefaultTimeoutMs  = 3000
)

var (
	// ErrRawSocketUnsupported is sent when the pinger is configured to use raw sockets
	// when raw socket based pings are not supported on the system
	ErrRawSocketUnsupported = errors.New("raw socket cannot be used with this OS")
	// ErrUDPSocketUnsupported is sent when the pinger is configured to use UDP sockets
	// when UDP socket based pings are not supported on the system
	ErrUDPSocketUnsupported = errors.New("udp socket cannot be used with this OS")
)

type (
	// Config defines how pings should be run
	// across all hosts
	Config struct {
		// UseRawSocket determines the socket type to use
		// RAW or UDP
		UseRawSocket bool
		// Delay is the amount of time to wait between
		// sending ICMP packets, default is 1 second
		Delay time.Duration
		// Timeout is the total time to wait for all pings
		// to complete
		Timeout time.Duration
		// Count is the number of ICMP packets, pings, to send
		Count int
	}

	// Result encapsulates the results of a single run
	// of ping
	Result struct {
		// PacketsReceived is the number of packets received.
		PacketsReceived int `json:"packets_received"`
		// PacketsSent is the number of packets sent.
		PacketsSent int `json:"packets_sent"`
		// PacketsReceivedDuplicates is the number of duplicate responses there were to a sent packet.
		PacketsReceivedDuplicates int `json:"packets_received_duplicates"`
		// Rtts is the list of received round-trip-time in millisecond
		Rtts []float64 `json:"rtts"`
	}
)
