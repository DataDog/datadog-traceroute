// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package packets

import (
	"time"
)

func getReadTimeout(deadline time.Time) time.Duration {
	const (
		defaultTimeout = 1000 * time.Millisecond
		minTimeout     = 100 * time.Millisecond
	)
	// always return a timeout because we don't want the syscall to block forever
	if deadline.IsZero() {
		return defaultTimeout
	}

	timeout := time.Until(deadline)
	// I don't think timeouts are going to be that precise, so add a min timeout
	// to avoid making a syscall that is doomed to fail
	if timeout < minTimeout {
		return minTimeout
	}
	return timeout
}
