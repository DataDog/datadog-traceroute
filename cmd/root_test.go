// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package cmd

import (
	"context"
	"io"
	"strconv"
	"testing"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/result"
	"github.com/DataDog/datadog-traceroute/traceroute"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type captureTracerouteRunner struct {
	params traceroute.TracerouteParams
	calls  int
}

func (r *captureTracerouteRunner) RunTraceroute(_ context.Context, params traceroute.TracerouteParams) (*result.Results, error) {
	r.params = params
	r.calls++
	return &result.Results{}, nil
}

func executeTestCommand(t *testing.T, commandArgs ...string) (*captureTracerouteRunner, error) {
	t.Helper()

	cfg := &args{}
	runner := &captureTracerouteRunner{}
	cmd := newRootCmd(cfg, func() tracerouteRunner { return runner })
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	cmd.SetArgs(commandArgs)
	_, err := cmd.ExecuteC()
	return runner, err
}

func TestCLIFlagWiring(t *testing.T) {
	tests := []struct {
		name                 string
		args                 []string
		expectedProbeTimeout time.Duration
		expectedTotalTimeout time.Duration
		expectedMaxTTL       int
	}{
		{
			name:                 "defaults without total timeout",
			args:                 []string{"example.com"},
			expectedProbeTimeout: 3 * time.Second,
			expectedMaxTTL:       common.DefaultMaxTTL,
		},
		{
			name:                 "omitted probe timeout is derived from total timeout",
			args:                 []string{"--total-timeout-ms", "10000", "example.com"},
			expectedProbeTimeout: 300 * time.Millisecond,
			expectedTotalTimeout: 10 * time.Second,
			expectedMaxTTL:       common.DefaultMaxTTL,
		},
		{
			name:                 "derived timeout uses configured max TTL",
			args:                 []string{"--total-timeout-ms", "10000", "--max-ttl", "20", "example.com"},
			expectedProbeTimeout: 450 * time.Millisecond,
			expectedTotalTimeout: 10 * time.Second,
			expectedMaxTTL:       20,
		},
		{
			name:                 "explicit probe timeout is preserved",
			args:                 []string{"--total-timeout-ms", "10000", "--timeout", "500", "example.com"},
			expectedProbeTimeout: 500 * time.Millisecond,
			expectedTotalTimeout: 10 * time.Second,
			expectedMaxTTL:       common.DefaultMaxTTL,
		},
		{
			name:                 "explicit zero probe timeout is treated as unset",
			args:                 []string{"--total-timeout-ms", "10000", "--timeout", "0", "example.com"},
			expectedProbeTimeout: 300 * time.Millisecond,
			expectedTotalTimeout: 10 * time.Second,
			expectedMaxTTL:       common.DefaultMaxTTL,
		},
		{
			name:                 "explicit zero probe timeout without total uses the legacy default",
			args:                 []string{"--timeout", "0", "example.com"},
			expectedProbeTimeout: 3 * time.Second,
			expectedMaxTTL:       common.DefaultMaxTTL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner, err := executeTestCommand(t, tt.args...)

			require.NoError(t, err)
			require.Equal(t, 1, runner.calls)
			assert.Equal(t, "example.com", runner.params.Hostname)
			assert.Equal(t, tt.expectedProbeTimeout, runner.params.Timeout)
			assert.Equal(t, tt.expectedTotalTimeout, runner.params.TotalTimeout)
			assert.Equal(t, tt.expectedMaxTTL, runner.params.MaxTTL)
		})
	}
}

func TestCLIValidationErrors(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		errContains string
	}{
		{
			name:        "negative probe timeout",
			args:        []string{"--timeout", "-1", "example.com"},
			errContains: "--timeout",
		},
		{
			name:        "negative total timeout",
			args:        []string{"--total-timeout-ms", "-1", "example.com"},
			errContains: "--total-timeout-ms",
		},
		{
			name:        "malformed total timeout",
			args:        []string{"--total-timeout-ms", "not-a-number", "example.com"},
			errContains: "invalid argument",
		},
		{
			name: "overflowing total timeout",
			args: []string{
				"--total-timeout-ms",
				strconv.FormatInt(common.MaxTimeoutMs+1, 10),
				"example.com",
			},
			errContains: "--total-timeout-ms",
		},
		{
			name:        "invalid max TTL",
			args:        []string{"--max-ttl", "0", "example.com"},
			errContains: "--max-ttl",
		},
		{
			name:        "negative traceroute query count",
			args:        []string{"--traceroute-queries", "-1", "example.com"},
			errContains: "--traceroute-queries",
		},
		{
			name: "excessive traceroute query count",
			args: []string{
				"--traceroute-queries",
				strconv.Itoa(common.MaxTracerouteQueries + 1),
				"example.com",
			},
			errContains: "--traceroute-queries",
		},
		{
			name: "excessive E2E query count",
			args: []string{
				"--e2e-queries",
				strconv.Itoa(common.MaxE2eQueries + 1),
				"example.com",
			},
			errContains: "--e2e-queries",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner, err := executeTestCommand(t, tt.args...)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
			assert.Zero(t, runner.calls, "invalid CLI input must be rejected before invoking the traceroute runner")
		})
	}
}
