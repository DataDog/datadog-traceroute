// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package cmd

import (
	"testing"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/stretchr/testify/require"
)

func TestValidateTimeoutMsCLI(t *testing.T) {
	require.NoError(t, common.ValidateTimeoutMs("--timeout", common.DefaultNetworkPathTimeout, common.MaxTimeoutMs))
	require.NoError(t, common.ValidateTimeoutMs("--timeout", 10*60*1000, common.MaxTimeoutMs), "values above 5 minutes must still be accepted for backward compatibility")
	require.Error(t, common.ValidateTimeoutMs("--timeout", -1, common.MaxTimeoutMs))
	require.Error(t, common.ValidateTimeoutMs("--total-timeout-ms", -1, common.MaxTimeoutMs))
	require.Error(t, common.ValidateTimeoutMs("--total-timeout-ms", int(common.MaxTimeoutMs)+1, common.MaxTimeoutMs))
	require.NoError(t, common.ValidateTimeoutMs("--total-timeout-ms", int(common.MaxTimeoutMs), common.MaxTimeoutMs))
}

func TestValidateMaxTTLCLI(t *testing.T) {
	require.NoError(t, common.ValidateMaxTTL("--max-ttl", common.DefaultMaxTTL))
	require.NoError(t, common.ValidateMaxTTL("--max-ttl", common.MaxAllowedTTL))
	require.Error(t, common.ValidateMaxTTL("--max-ttl", 0))
	require.Error(t, common.ValidateMaxTTL("--max-ttl", -1))
	require.Error(t, common.ValidateMaxTTL("--max-ttl", common.MaxAllowedTTL+1))
}
