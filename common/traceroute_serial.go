// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package common

import (
	"context"
	"fmt"
	"time"

	"github.com/DataDog/datadog-traceroute/log"
)

// TracerouteSerialParams are the parameters for TracerouteSerial
type TracerouteSerialParams struct {
	TracerouteParams
}

// TracerouteSerial runs a traceroute in serial. Sometimes this is necessary over TracerouteParallel
// because the driver doesn't support parallel.
func TracerouteSerial(ctx context.Context, t TracerouteDriver, p TracerouteSerialParams) ([]*ProbeResponse, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}

	results := make([]*ProbeResponse, int(p.MaxTTL)+1)
	for i := int(p.MinTTL); i <= int(p.MaxTTL); i++ {
		if ctx.Err() != nil {
			break
		}
		sendDelay := time.NewTimer(p.SendDelay)

		timeoutCtx, cancel := contextWithOptionalTimeout(ctx, p.TracerouteTimeout)

		err := t.SendProbe(uint8(i))
		if err != nil {
			cancel()
			sendDelay.Stop()
			return nil, fmt.Errorf("SendProbe() failed: %w", err)
		}

		var probe *ProbeResponse
		for probe == nil {
			if timeoutCtx.Err() != nil {
				break
			}

			probe, err = t.ReceiveProbe(p.PollFrequency)
			if CheckProbeRetryable("ReceiveProbe", err) {
				continue
			} else if err != nil {
				cancel()
				sendDelay.Stop()
				return nil, fmt.Errorf("ReceiveProbe() failed: %w", err)
			} else if err := p.validateProbe(probe); err != nil {
				cancel()
				sendDelay.Stop()
				return nil, err
			}
		}
		cancel()

		if probe != nil {
			log.Tracef("found probe %+v", probe)
			// if we found the destination, no need to keep going
			results[probe.TTL] = probe
			if probe.IsDest {
				sendDelay.Stop()
				break
			}
		}

		// wait for at least SendDelay to pass, but don't block past ctx being canceled/expired
		select {
		case <-sendDelay.C:
		case <-ctx.Done():
			sendDelay.Stop()
		}
	}

	// if we got externally cancelled, report that
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	return clipResults(p.MinTTL, results), nil
}
