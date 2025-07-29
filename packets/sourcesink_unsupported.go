// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build !darwin && !linux && !windows

package packets

import (
	"fmt"
	"net/netip"
)

// NewSourceSink returns a Source and Sink implementation for this platform
func NewSourceSink(_ netip.Addr) (SourceSinkHandle, error) {
	return SourceSinkHandle{}, fmt.Errorf("NewSourceSink: this platform is not supported")
}
