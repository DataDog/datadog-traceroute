// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package packets

import (
	"fmt"

	"golang.org/x/net/bpf"
)

// this is a simple BPF program that drops all packets no matter what
var dropAllFilter = []bpf.RawInstruction{
	{Op: 0x6, Jt: 0, Jf: 0, K: 0x00000000},
}

// icmpFilter is codegen'd from tcpdump -i eth0 -dd 'icmp || icmp6'
// It allows ICMPv4 and ICMPv6 traffic
var icmpFilter = []bpf.RawInstruction{
	{Op: 0x28, Jt: 0, Jf: 0, K: 0x0000000c},
	{Op: 0x15, Jt: 0, Jf: 2, K: 0x00000800},
	{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000017},
	{Op: 0x15, Jt: 6, Jf: 7, K: 0x00000001},
	{Op: 0x15, Jt: 0, Jf: 6, K: 0x000086dd},
	{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000014},
	{Op: 0x15, Jt: 3, Jf: 0, K: 0x0000003a},
	{Op: 0x15, Jt: 0, Jf: 3, K: 0x0000002c},
	{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000036},
	{Op: 0x15, Jt: 0, Jf: 1, K: 0x0000003a},
	{Op: 0x6, Jt: 0, Jf: 0, K: 0x00040000},
	{Op: 0x6, Jt: 0, Jf: 0, K: 0x00000000},
}

// udpFilter is codegen'd from tcpdump -i eth0 -dd 'icmp || icmp6 || udp'
// it allows ICMPv4, ICMPv6, and UDP traffic (basically it omits TCP)
var udpFilter = []bpf.RawInstruction{
	{Op: 0x28, Jt: 0, Jf: 0, K: 0x0000000c},
	{Op: 0x15, Jt: 0, Jf: 2, K: 0x00000800},
	{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000017},
	{Op: 0x15, Jt: 7, Jf: 6, K: 0x00000001},
	{Op: 0x15, Jt: 0, Jf: 7, K: 0x000086dd},
	{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000014},
	{Op: 0x15, Jt: 4, Jf: 0, K: 0x0000003a},
	{Op: 0x15, Jt: 0, Jf: 2, K: 0x0000002c},
	{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000036},
	{Op: 0x15, Jt: 1, Jf: 0, K: 0x0000003a},
	{Op: 0x15, Jt: 0, Jf: 1, K: 0x00000011},
	{Op: 0x6, Jt: 0, Jf: 0, K: 0x00040000},
	{Op: 0x6, Jt: 0, Jf: 0, K: 0x00000000},
}

// synackFilter is codegen'd from:
// tcpdump -i eth0 -dd 'tcp[tcpflags] & tcp-syn != 0 && tcp[tcpflags] & tcp-ack != 0'
// It allows only TCP SYNACK packets
var tcpSynackFilter = []bpf.RawInstruction{
	{Op: 0x28, Jt: 0, Jf: 0, K: 0x0000000c},
	{Op: 0x15, Jt: 0, Jf: 9, K: 0x00000800},
	{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000017},
	{Op: 0x15, Jt: 0, Jf: 7, K: 0x00000006},
	{Op: 0x28, Jt: 0, Jf: 0, K: 0x00000014},
	{Op: 0x45, Jt: 5, Jf: 0, K: 0x00001fff},
	{Op: 0xb1, Jt: 0, Jf: 0, K: 0x0000000e},
	{Op: 0x50, Jt: 0, Jf: 0, K: 0x0000001b},
	{Op: 0x45, Jt: 0, Jf: 2, K: 0x00000002},
	{Op: 0x45, Jt: 0, Jf: 1, K: 0x00000010},
	{Op: 0x6, Jt: 0, Jf: 0, K: 0x00040000},
	{Op: 0x6, Jt: 0, Jf: 0, K: 0x00000000},
}

func getClassicBPFFilter(spec PacketFilterSpec) ([]bpf.RawInstruction, error) {
	switch spec.FilterType {
	case FilterTypeNone:
		return nil, fmt.Errorf("FilterTypeNone isn't a filter")
	case FilterTypeICMP:
		return icmpFilter, nil
	case FilterTypeUDP:
		return udpFilter, nil
	case FilterTypeTCP:
		return spec.TCPFilterConfig.GenerateTCP4Filter()
	case FilterTypeSYNACK:
		return tcpSynackFilter, nil
	default:
		return nil, fmt.Errorf("Unknown filter type %d", spec.FilterType)
	}
}
