// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build windows

package packets

import (
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/network/driver"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// pipeHandle stands in for the driver handle: only the methods Close uses are implemented.
type pipeHandle struct {
	driver.Handle
	h windows.Handle
}

func (p *pipeHandle) CancelIoEx(ol *windows.Overlapped) error { return windows.CancelIoEx(p.h, ol) }
func (p *pipeHandle) Close() error                            { return windows.CloseHandle(p.h) }

// TestCloseWaitsForCancelledReads uses a named pipe in place of the driver, so the reads,
// their cancellation and the completion port behave as they do with the driver.
func TestCloseWaitsForCancelledReads(t *testing.T) {
	name, err := windows.UTF16PtrFromString(fmt.Sprintf(`\\.\pipe\datadog-traceroute-test-%d-%d`, os.Getpid(), time.Now().UnixNano()))
	require.NoError(t, err)
	server, err := windows.CreateNamedPipe(name,
		windows.PIPE_ACCESS_INBOUND|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_WAIT,
		1, 0, 4096, 0, nil)
	require.NoError(t, err)
	client, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	require.NoError(t, err)
	defer windows.CloseHandle(client)

	const count, written = 8, 3
	iocp, buffers, err := prepareCompletionBuffers(server, count)
	require.NoError(t, err)
	d := &SourceDriver{handle: &pipeHandle{h: server}, iocp: iocp, readBuffers: buffers, pendingReads: count}

	// complete some reads with data, as packets arriving before Close would
	for i := 0; i < written; i++ {
		var n uint32
		require.NoError(t, windows.WriteFile(client, []byte("packet"), &n, nil))
	}

	// the other reads are still pending, so they must not count as done
	require.False(t, d.waitForPendingReads(100*time.Millisecond))
	require.Equal(t, count-written, d.pendingReads)

	// Close cancels them, and must dequeue each completion before freeing the buffers
	require.NoError(t, d.Close())
	require.Zero(t, d.pendingReads)
	require.Nil(t, d.readBuffers)
}

func TestCreatePacketFilters(t *testing.T) {
	driver := &SourceDriver{}

	// Test TCP filter creation
	filters, err := driver.createPacketFilters(PacketFilterSpec{
		FilterType: FilterTypeTCP,
		FilterConfig: FilterConfig{
			Src: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 53),
			Dst: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 53),
		},
	})
	require.NoError(t, err)
	require.Len(t, filters, 4) // ICMP + TCP filter v4 + discard

	require.Equal(t, filters[0].Af, uint64(windows.AF_INET))
	// ipv6 icmp filter
	require.Equal(t, filters[1].Af, uint64(windows.AF_INET6))
	require.Equal(t, filters[2].Af, uint64(windows.AF_INET))
	// discard filter
	require.Equal(t, filters[3].Af, uint64(windows.AF_INET))

	// Test SYNACK filter creation
	driver3 := &SourceDriver{}
	filters, err = driver3.createPacketFilters(PacketFilterSpec{
		FilterType: FilterTypeSYNACK,
		FilterConfig: FilterConfig{
			Src: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 53),
		},
	})
	require.NoError(t, err)
	require.Len(t, filters, 4)

	require.Equal(t, filters[0].Af, uint64(windows.AF_INET))
	// ipv6 icmp filter
	require.Equal(t, filters[1].Af, uint64(windows.AF_INET6))
	require.Equal(t, filters[2].Af, uint64(windows.AF_INET))
	// discard filter
	require.Equal(t, filters[3].Af, uint64(windows.AF_INET))

	// Test UDP filter creation
	driver4 := &SourceDriver{}
	filters, err = driver4.createPacketFilters(PacketFilterSpec{
		FilterType: FilterTypeUDP,
	})
	require.NoError(t, err)
	require.Len(t, filters, 2) // only icmp filters (ipv4 and ipv6)

	// create ipv6 filter for tcp traffic
	driver5 := &SourceDriver{}
	filters, err = driver5.createPacketFilters(PacketFilterSpec{
		FilterType: FilterTypeTCP,
		FilterConfig: FilterConfig{
			Src: netip.AddrPortFrom(netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), 53),
			Dst: netip.AddrPortFrom(netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), 53),
		},
	})
	require.NoError(t, err)
	require.Len(t, filters, 4) // ICMP + TCP filter v4 + discard
	// initial ping filter (ipv4)
	require.Equal(t, filters[0].Af, uint64(windows.AF_INET))
	require.Equal(t, filters[1].Af, uint64(windows.AF_INET6))
	require.Equal(t, filters[2].Af, uint64(windows.AF_INET6))
	// discard filter
	require.Equal(t, filters[3].Af, uint64(windows.AF_INET6))

	// create ipv6 filter for synack traffic
	driver6 := &SourceDriver{}
	filters, err = driver6.createPacketFilters(PacketFilterSpec{
		FilterType: FilterTypeSYNACK,
		FilterConfig: FilterConfig{
			Src: netip.AddrPortFrom(netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), 53),
			Dst: netip.AddrPortFrom(netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), 53),
		},
	})
	require.NoError(t, err)
	require.Len(t, filters, 4) // ICMP + SYNACK filter v6 + discard
	// initial ping filter (ipv4)
	require.Equal(t, filters[0].Af, uint64(windows.AF_INET))
	require.Equal(t, filters[1].Af, uint64(windows.AF_INET6))
	require.Equal(t, filters[2].Af, uint64(windows.AF_INET6))
	// discard filter
	require.Equal(t, filters[3].Af, uint64(windows.AF_INET6))
}
