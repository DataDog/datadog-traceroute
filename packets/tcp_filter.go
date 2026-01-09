// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package packets

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"golang.org/x/net/bpf"
)

// FilterConfig is the config for GenerateTCP4Filter
type FilterConfig struct {
	Src netip.AddrPort
	Dst netip.AddrPort
}

// GenerateTCP4Filter creates a classic BPF filter for TCP SOCK_RAW sockets.
// It will only allow packets whose tuple matches the given config.
func (c FilterConfig) GenerateTCP4Filter() ([]bpf.RawInstruction, error) {
	if !c.Src.Addr().Is4() || !c.Dst.Addr().Is4() {
		return nil, fmt.Errorf("GenerateTCP4Filter2: src=%s and dst=%s must be IPv4", c.Src.Addr(), c.Dst.Addr())
	}
	srcAddr := binary.BigEndian.Uint32(c.Src.Addr().AsSlice())
	dstAddr := binary.BigEndian.Uint32(c.Dst.Addr().AsSlice())
	srcPort := uint32(c.Src.Port())
	dstPort := uint32(c.Dst.Port())

	// The packet source can yield either Ethernet-framed packets or raw IP packets (no link header),
	// depending on the interface (e.g., WireGuard is often L3-only). This filter supports both.
	//
	// For TCP traceroute we want:
	// - all ICMPv4 packets (TTL exceeded, unreachable, etc.)
	// - TCP packets matching a specific 4-tuple
	//
	// We only support IPv4 here.
	return bpf.Assemble([]bpf.Instruction{
		// A = packet[0] & 0xf0
		bpf.LoadAbsolute{Size: 1, Off: 0},
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf0},

		// --- Raw IPv4 block (size 17) ---
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40, SkipTrue: 0, SkipFalse: 17},
		// (raw) protocol
		bpf.LoadAbsolute{Size: 1, Off: 9},
		// accept ICMPv4
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 1, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: bpfMaxPacketLen},
		// require TCP
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipTrue: 0, SkipFalse: 12},
		// src/dst IPs
		bpf.LoadAbsolute{Size: 4, Off: 12},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: srcAddr, SkipTrue: 0, SkipFalse: 10},
		bpf.LoadAbsolute{Size: 4, Off: 16},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: dstAddr, SkipTrue: 0, SkipFalse: 8},
		// fragment check
		bpf.LoadAbsolute{Size: 2, Off: 6},
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 6, SkipFalse: 0},
		// x = ip header length
		bpf.LoadMemShift{Off: 0},
		// src/dst ports
		bpf.LoadIndirect{Size: 2, Off: 0},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: srcPort, SkipTrue: 0, SkipFalse: 3},
		bpf.LoadIndirect{Size: 2, Off: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: dstPort, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.RetConstant{Val: 0},

		// Drop raw IPv6 quickly; we only support IPv4 here.
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x60, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: 0},

		// --- Ethernet IPv4 ---
		bpf.LoadAbsolute{Size: 2, Off: 12}, // EtherType
		// If not IPv4, drop.
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipTrue: 1, SkipFalse: 0},
		bpf.RetConstant{Val: 0},

		// Ethernet IPv4 block (size 17)
		bpf.LoadAbsolute{Size: 1, Off: 23}, // Protocol (14 + 9)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 1, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipTrue: 0, SkipFalse: 12},
		bpf.LoadAbsolute{Size: 4, Off: 26}, // src IP (14 + 12)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: srcAddr, SkipTrue: 0, SkipFalse: 10},
		bpf.LoadAbsolute{Size: 4, Off: 30}, // dst IP (14 + 16)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: dstAddr, SkipTrue: 0, SkipFalse: 8},
		bpf.LoadAbsolute{Size: 2, Off: 20}, // fragment offset (14 + 6)
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 6, SkipFalse: 0},
		bpf.LoadMemShift{Off: 14},
		bpf.LoadIndirect{Size: 2, Off: 14}, // src port (14 + IP header len)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: srcPort, SkipTrue: 0, SkipFalse: 3},
		bpf.LoadIndirect{Size: 2, Off: 16}, // dst port
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: dstPort, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: bpfMaxPacketLen},
		bpf.RetConstant{Val: 0},
	})
}
