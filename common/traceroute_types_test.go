// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package common

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/DataDog/datadog-traceroute/result"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockDriver struct {
	t      *testing.T
	params TracerouteParams

	sentTTLs map[uint8]struct{}

	info           TracerouteDriverInfo
	sendHandler    func(ttl uint8) error
	receiveHandler func() (*ProbeResponse, error)
}

var parallelInfo = TracerouteDriverInfo{
	SupportsParallel: true,
}

func initMockDriver(t *testing.T, params TracerouteParams, info TracerouteDriverInfo) *MockDriver {
	return &MockDriver{
		t:              t,
		params:         params,
		info:           info,
		sentTTLs:       make(map[uint8]struct{}),
		sendHandler:    nil,
		receiveHandler: nil,
	}
}

func (m *MockDriver) GetDriverInfo() TracerouteDriverInfo {
	return m.info
}

func (m *MockDriver) SendProbe(ttl uint8) error {
	require.NotContains(m.t, m.sentTTLs, ttl, "same TTL sent twice")
	m.sentTTLs[ttl] = struct{}{}

	m.t.Logf("wrote %d\n", ttl)
	if m.sendHandler == nil {
		return nil
	}
	return m.sendHandler(ttl)
}

func (m *MockDriver) ReceiveProbe(timeout time.Duration) (*ProbeResponse, error) {
	require.Equal(m.t, m.params.PollFrequency, timeout)

	if m.receiveHandler == nil {
		return pollData(nil, timeout)
	}
	res, err := m.receiveHandler()
	var errNoPkt *ReceiveProbeNoPktError
	if !errors.As(err, &errNoPkt) {
		m.t.Logf("read %+v, %v\n", res, err)
	}
	return res, err
}

func pollData(receiveProbes chan *ProbeResponse, pollFrequency time.Duration) (*ProbeResponse, error) {
	noData := &ReceiveProbeNoPktError{Err: fmt.Errorf("testing, no data")}
	after := time.After(pollFrequency)
	select {
	case probe := <-receiveProbes:
		if probe == nil {
			<-after
			return nil, noData
		}
		return probe, nil
	case <-after:
		return nil, noData
	}
}

func TestClipResultsDest(t *testing.T) {
	results := []*ProbeResponse{
		nil,
		{TTL: 1, IsDest: false},
		{TTL: 2, IsDest: false},
		{TTL: 3, IsDest: true},
		nil,
	}

	clipped := clipResults(1, results)
	require.Equal(t, results[1:4], clipped)
}

func TestClipResultsNoDest(t *testing.T) {
	results := []*ProbeResponse{
		nil,
		{TTL: 1, IsDest: false},
		{TTL: 2, IsDest: false},
		{TTL: 3, IsDest: false},
		nil,
	}

	clipped := clipResults(1, results)
	require.Equal(t, results[1:], clipped)
}

func TestClipResultsMinTTL(t *testing.T) {
	results := []*ProbeResponse{
		nil,
		nil,
		{TTL: 2, IsDest: false},
		{TTL: 3, IsDest: false},
		nil,
	}

	clipped := clipResults(2, results)
	require.Equal(t, results[2:], clipped)
}

func TestToHops(t *testing.T) {
	results := []*ProbeResponse{
		{IP: netip.AddrFrom4([4]byte{10, 0, 0, 10}), TTL: 1, IsDest: false, RTT: time.Duration(10) * time.Millisecond},
		nil,
		{IP: netip.AddrFrom4([4]byte{10, 0, 0, 20}), TTL: 3, IsDest: true, RTT: time.Duration(20) * time.Millisecond},
	}
	hops, err := ToHops(TracerouteParams{MinTTL: 1}, results)
	assert.NoError(t, err)
	expectedHops := []*result.TracerouteHop{
		{
			TTL:       1,
			IPAddress: net.IP{10, 0, 0, 10},
			RTT:       0.01,
			IsDest:    false,
			Reachable: true,
		},
		{
			TTL: 2,
		},
		{
			TTL:       3,
			IPAddress: net.IP{10, 0, 0, 20},
			RTT:       0.02,
			Reachable: true,
			IsDest:    true,
		},
	}
	assert.Equal(t, hops, expectedHops)
}
