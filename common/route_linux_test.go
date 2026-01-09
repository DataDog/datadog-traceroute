// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build linux

package common

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsERANGE(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "ERANGE error",
			err:      syscall.ERANGE,
			expected: true,
		},
		{
			name:     "other syscall error",
			err:      syscall.EINVAL,
			expected: false,
		},
		{
			name:     "wrapped ERANGE error",
			err:      fmt.Errorf("wrapper: %w", syscall.ERANGE),
			expected: true,
		},
		{
			name:     "error message contains numerical result out of range",
			err:      errors.New("failed: numerical result out of range"),
			expected: true,
		},
		{
			name:     "generic error",
			err:      errors.New("some error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isERANGE(tt.err)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestGetRouteInfo(t *testing.T) {
	t.Run("loopback destination", func(t *testing.T) {
		info, err := GetRouteInfo(net.ParseIP("127.0.0.1"))
		require.NoError(t, err)
		require.NotNil(t, info)
		require.NotNil(t, info.SrcIP)
		require.True(t, info.SrcIP.IsLoopback())
	})

	t.Run("external destination fallback works", func(t *testing.T) {
		// This tests that even if netlink returns empty routes,
		// the fallback still works
		info, err := GetRouteInfo(net.ParseIP("8.8.8.8"))
		require.NoError(t, err)
		require.NotNil(t, info)
		require.NotNil(t, info.SrcIP)
	})
}

func TestGetRouteInfoFallback(t *testing.T) {
	t.Run("loopback destination fallback", func(t *testing.T) {
		info, err := getRouteInfoFallback(net.ParseIP("127.0.0.1"))
		require.NoError(t, err)
		require.NotNil(t, info)
		require.NotNil(t, info.SrcIP)
	})

	t.Run("external destination fallback", func(t *testing.T) {
		info, err := getRouteInfoFallback(net.ParseIP("8.8.8.8"))
		require.NoError(t, err)
		require.NotNil(t, info)
		require.NotNil(t, info.SrcIP)
		require.Equal(t, 0, info.InterfaceIndex)
	})
}
