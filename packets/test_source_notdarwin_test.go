// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build test && !darwin && !windows && root

package packets

import (
	"errors"
	"net/netip"
)

func newTestSourceForLoopback() (Source, func() error, error) {
	handle, err := NewSourceSink(netip.MustParseAddr("127.0.0.1"), true)
	if err != nil {
		return nil, nil, err
	}
	return handle.Source, func() error {
		return errors.Join(handle.Source.Close(), handle.Sink.Close())
	}, nil
}
