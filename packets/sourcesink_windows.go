// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build windows

package packets

import (
	"fmt"
	"net/netip"
)

// NewSourceSink returns a Source and Sink implementation for this platform
func NewSourceSink(addr netip.Addr) (SourceSinkHandle, error) {
	rawConn, err := NewRawConn(addr)
	if err != nil {
		return SourceSinkHandle{}, fmt.Errorf("NewSourceSink failed to init rawConn: %w", err)
	}
	return SourceSinkHandle{
		Source:        rawConn,
		Sink:          rawConn,
		MustClosePort: true,
	}, nil
}
