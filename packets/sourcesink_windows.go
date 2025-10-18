// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build windows

package packets

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/DataDog/datadog-agent/pkg/network/driver"
)

var initOnce sync.Once

// StartDriver starts the driver
// this is to be used in traceroutes run outside of the agent
// as the traceroute module will init and start the driver in the agent
func StartDriver() error {
	var initErr error
	initOnce.Do(func() {
		initErr = driver.Init()
	})
	err := initErr
	if err != nil {
		return fmt.Errorf("StartDriver failed to init driver: %w", err)
	}
	err = driver.Start()
	if err != nil {
		return fmt.Errorf("StartDriver failed to start driver: %w", err)
	}

	return nil
}

// NewSourceSink returns a Source and Sink implementation for this platform
func NewSourceSink(addr netip.Addr, useDriver bool) (SourceSinkHandle, error) {
	if useDriver {
		return NewSourceSinkDriver(addr)
	}
	return NewSourceSinkRaw(addr)
}

func NewSourceSinkDriver(addr netip.Addr) (SourceSinkHandle, error) {
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

// NewSourceSinkRaw returns a Source and Sink implementation for this platform
// that uses a raw socket
func NewSourceSinkRaw(addr netip.Addr) (SourceSinkHandle, error) {
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
