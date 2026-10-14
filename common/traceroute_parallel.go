// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package common

import (
	"context"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/DataDog/datadog-traceroute/log"
)

// TracerouteParallelParams are the parameters for TracerouteParallel
type TracerouteParallelParams struct {
	TracerouteParams
}

// MaxTimeout combines the timeout and probe delays into a total timeout for the
// traceroute. Saturating preserves a finite deadline when a valid public timeout near
// time.Duration's limit would otherwise wrap negative and be interpreted as disabled.
func (p TracerouteParallelParams) MaxTimeout() time.Duration {
	probeCount := time.Duration(p.ProbeCount())
	if p.SendDelay > 0 && probeCount > time.Duration(math.MaxInt64)/p.SendDelay {
		return time.Duration(math.MaxInt64)
	}
	delaySum := p.SendDelay * probeCount
	if delaySum > 0 && p.TracerouteTimeout > time.Duration(math.MaxInt64)-delaySum {
		return time.Duration(math.MaxInt64)
	}
	return p.TracerouteTimeout + delaySum
}

// TracerouteParallel runs a traceroute in parallel
func TracerouteParallel(ctx context.Context, t TracerouteDriver, p TracerouteParallelParams) ([]*ProbeResponse, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}

	info := t.GetDriverInfo()
	if !info.SupportsParallel {
		return nil, fmt.Errorf("tried to call TracerouteParallel on a TracerouteDriver that doesn't support parallel")
	}

	results := make([]*ProbeResponse, int(p.MaxTTL)+1)
	// The sender publishes which TTLs belong to this run before sending them so the
	// receiver can reject stale responses for probes this run has not sent.
	probeSent := make([]atomic.Bool, int(p.MaxTTL)+1)
	writeProbe := func(probe *ProbeResponse) {
		log.Tracef("found probe %+v", probe)
		previous := results[probe.TTL]

		// packets can get delivered twice - only use the first received probe to avoid overestimating RTT.
		// this is also important for SACK because SACK traceroute returns the lowest TTL found from ACKs
		shouldUpdate := previous == nil
		// but also just in case, never let ICMP responses "cover up" actual destination responses
		if previous != nil && !previous.IsDest && probe.IsDest {
			shouldUpdate = true
		}

		if shouldUpdate {
			results[probe.TTL] = probe
		}
	}

	var timeout time.Duration
	if p.TracerouteTimeout > 0 {
		timeout = p.MaxTimeout()
	}
	timeoutCtx, cancel := contextWithOptionalTimeout(ctx, timeout)
	defer cancel()

	g, groupCtx := errgroup.WithContext(timeoutCtx)
	writerCtx, writerCancel := context.WithCancel(groupCtx)
	defer writerCancel()

	hasSent := make(chan struct{})

	// start a goroutine to SendProbe() in a loop
	g.Go(func() error {
		var sentOnce sync.Once
		defer sentOnce.Do(func() { close(hasSent) })

		for i := int(p.MinTTL); i <= int(p.MaxTTL); i++ {
			// leave if we got cancelled
			if writerCtx.Err() != nil {
				return nil
			}

			// Publish before SendProbe so even a driver that receives a response
			// immediately cannot race ahead of the active-probe bookkeeping.
			probeSent[i].Store(true)

			err := t.SendProbe(uint8(i))
			if err != nil {
				return fmt.Errorf("SendProbe() failed: %w", err)
			}
			sentOnce.Do(func() { close(hasSent) })

			// wait for at least SendDelay to pass, but don't block past writerCtx being canceled/expired
			timer := time.NewTimer(p.SendDelay)
			select {
			case <-timer.C:
			case <-writerCtx.Done():
				timer.Stop()
			}
		}
		return nil
	})

	g.Go(func() error {
		// Windows raw sockets don't let you read from them until you send something first.
		// If you try to read first, you will get WSAEINVAL. So wait until we send something
		<-hasSent
		for {
			// leave if we got cancelled, SendProbe() failed, etc
			// doesn't use writerCtx because when we find the destination, we writerCancel(), and we want to keep reading
			if groupCtx.Err() != nil {
				return nil
			}

			probe, err := t.ReceiveProbe(p.PollFrequency)
			if CheckProbeRetryable("ReceiveProbe", err) {
				continue
			} else if err != nil {
				return fmt.Errorf("ReceiveProbe() failed: %w", err)
			} else if err = p.validateProbe(probe); err != nil {
				return err
			}

			if !probeSent[probe.TTL].Load() {
				// A response for a TTL that has not been sent by this run cannot belong
				// to one of its active probes.
				continue
			}
			writeProbe(probe)
			// no need to send more probes if we found the destination
			if probe.IsDest {
				writerCancel()
				// A one-probe run has no lower-TTL responses left to collect. This is
				// the E2E query shape, so return its successful response immediately
				// instead of waiting for the per-probe context to expire.
				if p.ProbeCount() == 1 {
					return nil
				}
			}
		}
	})

	// check for an error from the goroutines
	err := g.Wait()
	if err != nil {
		return nil, err
	}

	// finally, if we got externally cancelled, report that
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	return clipResults(p.MinTTL, results), nil
}
