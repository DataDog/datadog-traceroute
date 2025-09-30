// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build unix

// Package tcp adds a TCP traceroute implementation to the agent
package tcp

import (
	"fmt"

	"github.com/DataDog/datadog-traceroute/result"
)

// TracerouteSequentialSocket is not supported on unix
func (t *TCPv4) TracerouteSequentialSocket() (*result.TracerouteRun, error) {
	// not implemented or supported on unix
	return nil, fmt.Errorf("not implemented or supported on unix")
}
