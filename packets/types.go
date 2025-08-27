// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package packets

// SourceSinkHandle contains a platform's Source and Sink implementation
type SourceSinkHandle struct {
	Source Source
	Sink   Sink
	// MustClosePort means the traceroute must close the handle they used to reserve a port.
	// It's a Windows-specific hack -- on Windows, you can't actually capture all
	// packets with a raw socket.  By reserving a port, packets go to that socket instead of your
	// raw socket. This can only be addressed using a Windows driver.
	MustClosePort bool
}

// PacketFilterType is which kind of packet filter to enable
type PacketFilterType int

const (
	// FilterTypeNone indicates no filter (all packets).
	FilterTypeNone PacketFilterType = iota
	// FilterTypeICMP indicates only ICMP packets.
	FilterTypeICMP
	// FilterTypeUDP indicates only ICMP and UDP packets.
	// FilterConfig will contain the UDP source/destination 4-tuple.
	FilterTypeUDP
	// FilterTypeTCP indicates only ICMP and TCP packets.
	// FilterConfig will contain the TCP source/destination 4-tuple.
	FilterTypeTCP
	// FilterTypeSYNACK indicates only TCP SYNACK packets.
	// FilterConfig will contain the source addr/port, but NOT the destination.
	// This is used by SACK traceroute.
	FilterTypeSYNACK
)

// PacketFilterSpec defines how a packet Source should filter packets.
type PacketFilterSpec struct {
	// FilterType is which kind of packet filter to enable
	FilterType PacketFilterType
	// FilterConfig contains the 4-tuple of source/dest.
	// Some fields may be unused for certain PacketFilterTypes -- refer
	// to the PacketFilterType documentation
	FilterConfig FilterConfig
}
