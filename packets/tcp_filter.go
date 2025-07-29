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

// TCPFilterConfig is the config for GenerateTCP4Filter
type TCPFilterConfig struct {
	Src netip.AddrPort
	Dst netip.AddrPort
}

// GenerateTCP4Filter creates a classic BPF filter for TCP SOCK_RAW sockets.
// It will only allow packets whose tuple matches the given config.
func (c TCPFilterConfig) GenerateTCP4Filter() ([]bpf.RawInstruction, error) {
	if !c.Src.Addr().Is4() || !c.Dst.Addr().Is4() {
		return nil, fmt.Errorf("GenerateTCP4Filter2: src=%s and dst=%s must be IPv4", c.Src.Addr(), c.Dst.Addr())
	}
	srcAddr := binary.BigEndian.Uint32(c.Src.Addr().AsSlice())
	dstAddr := binary.BigEndian.Uint32(c.Dst.Addr().AsSlice())
	srcPort := uint32(c.Src.Port())
	dstPort := uint32(c.Dst.Port())

	// Process to derive the following program:
	// 1. Generate the BPF program with placeholder values:
	//    tcpdump -i eth0 -d 'ip and tcp and src 2.4.6.8 and dst 1.3.5.7 and src port 1234 and dst port 5678'
	// 2. Replace the placeholder values with src/dst AddrPorts
	return bpf.Assemble([]bpf.Instruction{
		// (000) ldh      [12] -- load EtherType
		bpf.LoadAbsolute{Size: 2, Off: 12},
		// (001) jeq      #0x800           jt 2	jf 17 -- if IPv4, continue, else drop
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipTrue: 0, SkipFalse: 15},
		// (002) ldb      [23] -- load Protocol
		bpf.LoadAbsolute{Size: 1, Off: 23},
		// (003) jeq      #0x1             jt 16	jf 4 -- if ICMPv4, accept packet, else continue
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x1, SkipTrue: 12, SkipFalse: 0},
		// (004) jeq      #0x6             jt 5	jf 17 -- if TCP, continue, else drop
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipTrue: 0, SkipFalse: 12},
		// (005) ld       [26] -- load source IP
		bpf.LoadAbsolute{Size: 4, Off: 26},
		// (006) jeq      #0x2040608       jt 7	jf 17 -- if srcAddr matches, continue, else drop
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: srcAddr, SkipTrue: 0, SkipFalse: 10},
		// (007) ld       [30] -- load destination IP
		bpf.LoadAbsolute{Size: 4, Off: 30},
		// (008) jeq      #0x1030507       jt 9	jf 17 -- if dstAddr matches, continue, else drop
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: dstAddr, SkipTrue: 0, SkipFalse: 8},
		// (009) ldh      [20] -- load Fragment Offset
		bpf.LoadAbsolute{Size: 2, Off: 20},
		// (010) jset     #0x1fff          jt 17	jf 11 -- if fragmented, drop, else continue
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 6, SkipFalse: 0},
		// (011) ldxb     4*([14]&0xf) -- x = IP header length
		bpf.LoadMemShift{Off: 14},
		// (012) ldh      [x + 14] -- load source port
		bpf.LoadIndirect{Size: 2, Off: 14},
		// (013) jeq      #0x4d2           jt 14	jf 17 -- if srcPort matches, continue, else drop
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: srcPort, SkipTrue: 0, SkipFalse: 3},
		// (014) ldh      [x + 16] -- load destination port
		bpf.LoadIndirect{Size: 2, Off: 16},
		// (015) jeq      #0x162e          jt 16	jf 17 -- if dstPort matches, continue, else drop
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: dstPort, SkipTrue: 0, SkipFalse: 1},
		// (016) ret      #262144 -- accept packet
		bpf.RetConstant{Val: 262144},
		// (017) ret      #0  -- drop packet
		bpf.RetConstant{Val: 0},
	})
}
