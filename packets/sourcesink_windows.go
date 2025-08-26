// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build windows

package packets

import (
	"fmt"
	"net/netip"

	"github.com/DataDog/datadog-agent/pkg/network/driver"
)

// NewSourceSink returns a Source and Sink implementation for this platform
func NewSourceSink(addr netip.Addr) (SourceSinkHandle, error) {
	return NewSourceSinkDriver(addr)
}

func NewSourceSinkDriver(addr netip.Addr) (SourceSinkHandle, error) {
	// init the driver
	err := driver.Init()
	if err != nil {
		return SourceSinkHandle{}, fmt.Errorf("NewSourceSink failed to init driver: %w", err)
	}

	// start the driver
	err = driver.Start()
	if err != nil {
		return SourceSinkHandle{}, fmt.Errorf("NewSourceSink failed to start driver: %w", err)
	}

	// create new handles to the driver
	source, err := NewSourceDriver(addr)
	if err != nil {
		return SourceSinkHandle{}, fmt.Errorf("NewSourceSink failed to create source driver: %w", err)
	}

	// create a new sink driver
	sink, err := NewSinkDriver(addr)
	if err != nil {
		return SourceSinkHandle{}, fmt.Errorf("NewSourceSink failed to create sink driver: %w", err)
	}

	return SourceSinkHandle{
		Source:        source,
		Sink:          sink,
		MustClosePort: false,
	}, nil
}
