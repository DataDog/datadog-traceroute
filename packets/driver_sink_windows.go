// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows

package packets

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/DataDog/datadog-agent/pkg/network/driver"
	"golang.org/x/sys/windows"
)

type SinkDriver struct {
	closeOnce sync.Once
	handle    driver.Handle
}

var _ Sink = &SinkDriver{}

// NewSinkDriver creates a new SinkDriver for packet transmission.
func NewSinkDriver(addr netip.Addr) (Sink, error) {
	d := &SinkDriver{}
	var err error

	// create the handle
	d.handle, err = driver.NewHandle(0, driver.DataHandle, nil)
	if err != nil {
		return nil, fmt.Errorf("NewSinkDriver failed to create handle: %w", err)
	}

	return d, nil
}

// WriteTo writes the given packet (buffer starts at the IP layer) to addrPort.
func (d *SinkDriver) WriteTo(buf []byte, addrPort netip.AddrPort) error {
	// Write packet data directly to the device handle
	err := windows.WriteFile(d.handle.GetWindowsHandle(), buf, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to send packet via driver: %w", err)
	}

	return nil
}

// Close closes the driver handle.
func (d *SinkDriver) Close() error {
	var err error
	d.closeOnce.Do(func() {
		if d.handle != nil {
			err = d.handle.Close()
			if err != nil {
				err = fmt.Errorf("error closing driver sink handle: %w", err)
			}
		}
	})
	return err
}
