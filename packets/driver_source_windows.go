// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows

package packets

/*
#include <stdlib.h>
#include <memory.h>
*/
import "C"
import (
	"fmt"
	"net/netip"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/DataDog/datadog-agent/pkg/network/driver"
	"github.com/DataDog/datadog-traceroute/common"
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

const (
	readBufferCount = 100
)

type readbuffer struct {
	ol   windows.Overlapped
	data [1500]byte
}

type SourceDriver struct {
	closeOnce         sync.Once
	deadline          time.Time
	handle            driver.Handle
	iocp              windows.Handle
	filters           []PacketFilterSpec
	icmpFilterCreated bool
	readBuffers       []*readbuffer
}

var _ Source = &SourceDriver{}

// NewSourceDriver creates a new SourceDriver.
func NewSourceDriver(adr netip.Addr) (Source, error) {
	d := &SourceDriver{}
	var err error

	// create the handle
	d.handle, err = driver.NewHandle(windows.FILE_FLAG_OVERLAPPED, driver.DataHandle, nil)
	if err != nil {
		return nil, fmt.Errorf("NewSourceDriver failed to create handle: %w", err)
	}

	iocp, buffers, err := prepareCompletionBuffers(d.handle.GetWindowsHandle(), readBufferCount)
	if err != nil {
		return nil, fmt.Errorf("NewSourceDriver failed to prepare completion buffers: %w", err)
	}

	d.iocp = iocp
	d.readBuffers = buffers

	return d, nil
}

// SetDataFilters installs the provided filters for data
func (d *SourceDriver) SetDataFilters(filters []driver.FilterDefinition) error {
	var id int64
	for _, filter := range filters {
		err := d.handle.DeviceIoControl(
			driver.SetDataFilterIOCTL,
			(*byte)(unsafe.Pointer(&filter)),
			uint32(unsafe.Sizeof(filter)),
			(*byte)(unsafe.Pointer(&id)),
			uint32(unsafe.Sizeof(id)), nil, nil)
		if err != nil {
			return fmt.Errorf("failed to set filter: %v", err)
		}
	}
	return nil
}

func (d *SourceDriver) createPacketFilters(filter PacketFilterSpec) ([]driver.FilterDefinition, error) {
	var filters []driver.FilterDefinition
	// check if the filter is already set
	// if it is, don't create any filters
	for _, filt := range d.filters {
		if filt == filter {
			return filters, nil
		}
	}

	if !d.icmpFilterCreated {
		// create the icmp filter
		filters = append(filters,
			driver.FilterDefinition{
				FilterVersion:  driver.Signature,
				Size:           driver.FilterDefinitionSize,
				FilterLayer:    driver.LayerTransport,
				Af:             windows.AF_INET,
				InterfaceIndex: uint64(0),
				Direction:      driver.DirectionInbound,
				Protocol:       windows.IPPROTO_ICMP,
			},
			// create icmpv6 filter
			driver.FilterDefinition{
				FilterVersion:  driver.Signature,
				Size:           driver.FilterDefinitionSize,
				FilterLayer:    driver.LayerTransport,
				Af:             windows.AF_INET6,
				InterfaceIndex: uint64(0),
				Direction:      driver.DirectionInbound,
				Protocol:       windows.IPPROTO_ICMPV6,
			},
		)
		d.icmpFilterCreated = true
	}

	filterDefs, err := getWindowsFilter(filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get windows filter: %w", err)
	}

	// add the filter to the list of filters
	// this is used to avoid setting the same filter multiple times
	d.filters = append(d.filters, filter)

	// add the filter definitions to the list of filter definitions
	filters = append(filters, filterDefs...)

	return filters, nil
}

// SetPacketFilter sets the packet filter for the driver.
func (d *SourceDriver) SetPacketFilter(filter PacketFilterSpec) error {
	filterDefs, err := d.createPacketFilters(filter)
	if err != nil {
		return fmt.Errorf("failed to create packet filters: %w", err)
	}
	if len(filterDefs) == 0 {
		// no new filters to set
		return nil
	}
	return d.SetDataFilters(filterDefs)
}

// Close closes the driver.
func (d *SourceDriver) Close() error {
	var err error
	d.closeOnce.Do(func() {
		// destroy io completion port, and file
		if e := d.handle.CancelIoEx(nil); e != nil {
			err = fmt.Errorf("error cancelling DNS io completion: %w", e)
			return
		}
		if e := windows.CloseHandle(d.iocp); e != nil {
			err = fmt.Errorf("error closing DNS io completion handle: %w", e)
			return
		}
		if e := d.handle.Close(); e != nil {
			err = fmt.Errorf("error closing driver DNS h: %w", e)
			return
		}
		for _, buf := range d.readBuffers {
			C.free(unsafe.Pointer(buf))
		}
		d.readBuffers = nil
	})
	return err
}

// prepare N read buffers
// and return the IoCompletionPort that will be used to coordinate reads.
// danger: even though all reads will reference the returned iocp, buffers must be in-scope as long
// as reads are happening. Otherwise, the memory the kernel is writing to will be written to memory reclaimed
// by the GC
func prepareCompletionBuffers(h windows.Handle, count int) (iocp windows.Handle, buffers []*readbuffer, err error) {
	iocp, err = windows.CreateIoCompletionPort(h, windows.Handle(0), 0, 0)
	if err != nil {
		return windows.Handle(0), nil, errors.Wrap(err, "error creating IO completion port")
	}

	buffers = make([]*readbuffer, count)
	for i := 0; i < count; i++ {
		buf := (*readbuffer)(C.malloc(C.size_t(unsafe.Sizeof(readbuffer{}))))
		C.memset(unsafe.Pointer(buf), 0, C.size_t(unsafe.Sizeof(readbuffer{})))
		buffers[i] = buf

		err = windows.ReadFile(h, buf.data[:], nil, &(buf.ol))
		if err != nil && err != windows.ERROR_IO_PENDING {
			_ = windows.CloseHandle(iocp)
			return windows.Handle(0), nil, errors.Wrap(err, "failed to initiate readfile")
		}
	}

	return iocp, buffers, nil
}

// Read reads a packet from the driver.
func (d *SourceDriver) Read(buf []byte) (int, error) {
	var bytesRead uint32
	var key uintptr // returned by GetQueuedCompletionStatus, then ignored
	var ol *windows.Overlapped
	timeoutMs := uint32(getReadTimeout(d.deadline).Milliseconds())

	// NOTE: ideally we would pass a timeout of INFINITY to the GetQueuedCompletionStatus, but are using a
	// timeout of 0 and letting userspace do a busy loop to align better with the Linux code.
	err := windows.GetQueuedCompletionStatus(d.iocp, &bytesRead, &key, &ol, timeoutMs)
	if err != nil {
		if err == syscall.Errno(syscall.WAIT_TIMEOUT) {
			// this means that there was no queued completion status
			// this is a timeout, so we return the common ReceiveProbeNoPktError
			return 0, &common.ReceiveProbeNoPktError{Err: err}
		}

		return 0, errors.Wrap(err, "could not get queued completion status")
	}

	b := (*readbuffer)(unsafe.Pointer(ol))

	start := driver.FilterPacketHeaderSize

	length := copy(buf, b.data[start:])

	// kick off another read
	if err := windows.ReadFile(d.handle.GetWindowsHandle(), b.data[:], nil, &(b.ol)); err != nil && err != windows.ERROR_IO_PENDING {
		return 0, err
	}

	return length, nil
}

// SetReadDeadline sets the read deadline for the driver.
func (d *SourceDriver) SetReadDeadline(t time.Time) error {
	d.deadline = t
	return nil
}
