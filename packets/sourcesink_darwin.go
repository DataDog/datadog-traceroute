// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build darwin

package packets

import (
	"fmt"
	"net/netip"
)

// NewSourceSink returns a Source and Sink implementation for this platform
func NewSourceSink(addr netip.Addr, useDriver bool) (SourceSinkHandle, error) {
	sink, err := NewSinkDarwin(addr)
	if err != nil {
		return SourceSinkHandle{}, fmt.Errorf("NewSourceSink failed to make SinkLinux: %w", err)
	}

	source, err := NewBpfDevice(addr)
	if err != nil {
		sink.Close()
		return SourceSinkHandle{}, fmt.Errorf("NewSourceSink failed to make BpfDevice: %w", err)
	}

	return SourceSinkHandle{
		Source:        source,
		Sink:          sink,
		MustClosePort: false,
	}, nil
}

// StartDriver starts the driver
// as there is no driver for this platform, this is a no-op
func StartDriver() error {
	return nil
}
