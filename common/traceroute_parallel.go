// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package common

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/DataDog/datadog-traceroute/log"
)

// TracerouteParallelParams are the parameters for TracerouteParallel
type TracerouteParallelParams struct {
	TracerouteParams
}

// MaxTimeout combines the timeout+probe delays into a total timeout for the traceroute
func (p TracerouteParallelParams) MaxTimeout() time.Duration {
	delaySum := p.SendDelay * time.Duration(p.ProbeCount())
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
	resultsMu := sync.Mutex{}
	probeSentAt := make([]time.Time, int(p.MaxTTL)+1)
	probeSentAtMu := sync.RWMutex{}
	writeProbe := func(probe *ProbeResponse) {
		log.Tracef("found probe %+v", probe)
		resultsMu.Lock()
		defer resultsMu.Unlock()
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

			// Record the start before SendProbe so even a driver that receives a response
			// immediately cannot race ahead of the per-probe deadline bookkeeping.
			probeSentAtMu.Lock()
			probeSentAt[i] = time.Now()
			probeSentAtMu.Unlock()

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

			probeSentAtMu.RLock()
			sentAt := probeSentAt[probe.TTL]
			probeSentAtMu.RUnlock()
			if sentAt.IsZero() {
				// A response for a TTL that has not been sent by this run cannot belong
				// to one of its active probes.
				continue
			}
			if p.TracerouteTimeout > 0 && time.Since(sentAt) > p.TracerouteTimeout {
				log.Tracef("ignoring response for TTL %d received after per-probe timeout", probe.TTL)
				continue
			}

			writeProbe(probe)
			// no need to send more probes if we found the destination
			if probe.IsDest {
				writerCancel()
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
