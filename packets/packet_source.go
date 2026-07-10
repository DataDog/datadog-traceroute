// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

// Package packets has packet capture/emitting/filtering logic
package packets

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
)

//go:generate mockgen -source=$GOFILE -package=$GOPACKAGE -destination=packet_source_mockgen.go

// Source is an interface representing ethernet packet capture
type Source interface {
	// SetReadDeadline sets the deadline for when a Read() call must finish
	SetReadDeadline(t time.Time) error
	// Read reads a packet (starting with the IP frame)
	Read(buf []byte) (int, error)
	// Close closes the socket
	Close() error
	// SetPacketFilter sets this Source to only return certain packets.
	// This is purely a performance optimization -- on some platforms SetPacketFilter
	// may be a no-op.
	SetPacketFilter(spec PacketFilterSpec) error
}

// TimestampedSource is implemented by Sources that can report a kernel-provided
// capture timestamp for the most recently read packet, which is more accurate
// than a userspace time.Now() taken after Read() returns.
type TimestampedSource interface {
	// LastPacketTimestamp returns the kernel timestamp of the most recently
	// read packet, if available.
	LastPacketTimestamp() (time.Time, bool)
}

// ReadAndParse reads from the given source into the buffer, and parses it with parser.
// It returns the time the packet was received, preferring a kernel-provided
// timestamp (via TimestampedSource) over a userspace time.Now() when available.
func ReadAndParse(source Source, buffer []byte, parser *FrameParser) (time.Time, error) {
	n, err := source.Read(buffer)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return time.Time{}, &common.ReceiveProbeNoPktError{Err: err}
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("ConnHandle failed to Read: %w", err)
	}
	if n == 0 {
		return time.Time{}, fmt.Errorf("ConnHandle Read() returned 0 bytes")
	}

	receivedAt := time.Now()
	if ts, ok := source.(TimestampedSource); ok {
		if kernelTime, ok := ts.LastPacketTimestamp(); ok {
			receivedAt = kernelTime
		}
	}

	if err := parser.Parse(buffer[:n]); err != nil {
		return time.Time{}, err
	}

	return receivedAt, nil
}
