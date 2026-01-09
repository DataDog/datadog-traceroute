// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package packets

import (
	"fmt"
	"sync"

	"golang.org/x/net/bpf"
)

const bpfMaxPacketLen = 262144

// this is a simple BPF program that drops all packets no matter what
var dropAllFilter = []bpf.RawInstruction{
	{Op: 0x6, Jt: 0, Jf: 0, K: 0x00000000},
}

var (
	icmpFilterOnce sync.Once
	icmpFilterRaw  []bpf.RawInstruction
	icmpFilterErr  error

	udpFilterOnce sync.Once
	udpFilterRaw  []bpf.RawInstruction
	udpFilterErr  error

	tcpSynackFilterOnce sync.Once
	tcpSynackFilterRaw  []bpf.RawInstruction
	tcpSynackFilterErr  error
)

func getICMPFilter() ([]bpf.RawInstruction, error) {
	icmpFilterOnce.Do(func() {
		icmpFilterRaw, icmpFilterErr = generateICMPFilter()
	})
	return icmpFilterRaw, icmpFilterErr
}

func getUDPFilter() ([]bpf.RawInstruction, error) {
	udpFilterOnce.Do(func() {
		udpFilterRaw, udpFilterErr = generateUDPFilter()
	})
	return udpFilterRaw, udpFilterErr
}

func getTCPSynackFilter() ([]bpf.RawInstruction, error) {
	tcpSynackFilterOnce.Do(func() {
		tcpSynackFilterRaw, tcpSynackFilterErr = generateTCPSynackFilter()
	})
	return tcpSynackFilterRaw, tcpSynackFilterErr
}

// generateICMPFilter returns a classic BPF program that matches ICMPv4 and ICMPv6 packets.
//
// It supports both Ethernet-framed packets and raw IP packets (common on L3 interfaces like WireGuard).
func generateICMPFilter() ([]bpf.RawInstruction, error) {
	prog := []bpf.Instruction{
		// A = packet[0] & 0xf0 (upper nibble contains IP version for raw IP packets)
		bpf.LoadAbsolute{Size: 1, Off: 0},
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf0},

		// --- Raw IPv4 (no Ethernet header) ---
		// If version nibble == 4, check protocol at offset 9.
		// Block size: 4 instructions.
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40, SkipTrue: 0, SkipFalse: 4},
		bpf.LoadAbsolute{Size: 1, Off: 9},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 1, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.RetConstant{Val: 0},

		// --- Raw IPv6 (no Ethernet header) ---
		// Block size: 8 instructions.
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x60, SkipTrue: 0, SkipFalse: 8},
		bpf.LoadAbsolute{Size: 1, Off: 6}, // NextHeader
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 58, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 44, SkipTrue: 0, SkipFalse: 3}, // Fragment header
		bpf.LoadAbsolute{Size: 1, Off: 40},                                  // NextHeader after fragment header
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 58, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.RetConstant{Val: 0},

		// --- Ethernet-framed packets ---
		// Load EtherType.
		bpf.LoadAbsolute{Size: 2, Off: 12},

		// Ethernet IPv4 block (size 4).
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipTrue: 0, SkipFalse: 4},
		bpf.LoadAbsolute{Size: 1, Off: 23}, // IPv4.Protocol (14 + 9)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 1, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.RetConstant{Val: 0},

		// Ethernet IPv6 block (size 8).
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipTrue: 0, SkipFalse: 8},
		bpf.LoadAbsolute{Size: 1, Off: 20}, // IPv6.NextHeader (14 + 6)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 58, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 44, SkipTrue: 0, SkipFalse: 3}, // Fragment header
		bpf.LoadAbsolute{Size: 1, Off: 54},                                  // NextHeader after fragment header (14 + 40)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 58, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.RetConstant{Val: 0},

		// Non-IP packet.
		bpf.RetConstant{Val: 0},
	}
	return bpf.Assemble(prog)
}

// generateUDPFilter returns a classic BPF program that matches:
// - ICMPv4, ICMPv6 (and ICMPv6 after a fragment header)
// - UDPv4, UDPv6 (and UDPv6 after a fragment header)
//
// Like generateICMPFilter, it supports both Ethernet-framed packets and raw IP packets.
func generateUDPFilter() ([]bpf.RawInstruction, error) {
	prog := []bpf.Instruction{
		// A = packet[0] & 0xf0
		bpf.LoadAbsolute{Size: 1, Off: 0},
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf0},

		// --- Raw IPv4 (block size 6) ---
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40, SkipTrue: 0, SkipFalse: 6},
		bpf.LoadAbsolute{Size: 1, Off: 9},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 1, SkipTrue: 0, SkipFalse: 1}, // ICMPv4
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 0, SkipFalse: 1}, // UDP
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.RetConstant{Val: 0},

		// --- Raw IPv6 (block size 12) ---
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x60, SkipTrue: 0, SkipFalse: 12},
		bpf.LoadAbsolute{Size: 1, Off: 6},                                   // NextHeader
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 58, SkipTrue: 0, SkipFalse: 1}, // ICMPv6
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 0, SkipFalse: 1}, // UDP
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 44, SkipTrue: 0, SkipFalse: 5}, // Fragment header
		bpf.LoadAbsolute{Size: 1, Off: 40},                                  // NextHeader after fragment header
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 58, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.RetConstant{Val: 0},

		// --- Ethernet ---
		bpf.LoadAbsolute{Size: 2, Off: 12}, // EtherType

		// Ethernet IPv4 (block size 6)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipTrue: 0, SkipFalse: 6},
		bpf.LoadAbsolute{Size: 1, Off: 23},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 1, SkipTrue: 0, SkipFalse: 1}, // ICMPv4
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 0, SkipFalse: 1}, // UDP
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.RetConstant{Val: 0},

		// Ethernet IPv6 (block size 12)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipTrue: 0, SkipFalse: 12},
		bpf.LoadAbsolute{Size: 1, Off: 20}, // NextHeader (14 + 6)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 58, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 44, SkipTrue: 0, SkipFalse: 5}, // Fragment header
		bpf.LoadAbsolute{Size: 1, Off: 54},                                  // NextHeader after fragment header (14 + 40)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 58, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.RetConstant{Val: 0},

		// Non-IP packet.
		bpf.RetConstant{Val: 0},
	}
	return bpf.Assemble(prog)
}

// generateTCPSynackFilter returns a classic BPF program that matches IPv4 TCP packets where
// both SYN and ACK flags are set.
//
// It supports both Ethernet-framed packets and raw IPv4 packets.
func generateTCPSynackFilter() ([]bpf.RawInstruction, error) {
	prog := []bpf.Instruction{
		// A = packet[0] & 0xf0
		bpf.LoadAbsolute{Size: 1, Off: 0},
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf0},

		// --- Raw IPv4 (block size 10) ---
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40, SkipTrue: 0, SkipFalse: 10},
		bpf.LoadAbsolute{Size: 1, Off: 9},                                         // Protocol
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipTrue: 0, SkipFalse: 7},        // TCP
		bpf.LoadAbsolute{Size: 2, Off: 6},                                         // Fragment offset
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 5, SkipFalse: 0}, // Drop fragments
		bpf.LoadMemShift{Off: 0},                                                  // X = IP header length
		bpf.LoadIndirect{Size: 1, Off: 13},                                        // TCP flags
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x02, SkipTrue: 0, SkipFalse: 2},   // SYN
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x10, SkipTrue: 0, SkipFalse: 1},   // ACK
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.RetConstant{Val: 0},

		// Drop raw IPv6 quickly (avoid misclassifying IPv6 bytes as an Ethernet header).
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x60, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: 0},

		// --- Ethernet IPv4 ---
		bpf.LoadAbsolute{Size: 2, Off: 12}, // EtherType
		// If not IPv4, drop. Otherwise proceed.
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipTrue: 1, SkipFalse: 0},
		bpf.RetConstant{Val: 0},

		// Ethernet IPv4 SYNACK block (size 10)
		bpf.LoadAbsolute{Size: 1, Off: 23},                                        // Protocol (14 + 9)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipTrue: 0, SkipFalse: 7},        // TCP
		bpf.LoadAbsolute{Size: 2, Off: 20},                                        // Fragment offset (14 + 6)
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 5, SkipFalse: 0}, // Drop fragments
		bpf.LoadMemShift{Off: 14},                                                 // X = IP header length
		bpf.LoadIndirect{Size: 1, Off: 27},                                        // TCP flags (14 + 13)
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x02, SkipTrue: 0, SkipFalse: 2},   // SYN
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x10, SkipTrue: 0, SkipFalse: 1},   // ACK
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.RetConstant{Val: 0},
	}
	return bpf.Assemble(prog)
}

func getClassicBPFFilter(spec PacketFilterSpec) ([]bpf.RawInstruction, error) {
	switch spec.FilterType {
	case FilterTypeNone:
		return nil, fmt.Errorf("FilterTypeNone isn't a filter")
	case FilterTypeICMP:
		return getICMPFilter()
	case FilterTypeUDP:
		return getUDPFilter()
	case FilterTypeTCP:
		return spec.FilterConfig.GenerateTCP4Filter()
	case FilterTypeSYNACK:
		return getTCPSynackFilter()
	default:
		return nil, fmt.Errorf("Unknown filter type %d", spec.FilterType)
	}
}
