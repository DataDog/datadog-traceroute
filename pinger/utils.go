// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package pinger

import (
	"time"

	"github.com/DataDog/datadog-traceroute/log"
	probing "github.com/prometheus-community/pro-bing"
)

// RunPing creates a pinger for the requested host and sends the requested number of packets to it
func RunPing(cfg *Config, host string) (*Result, error) {
	pinger, err := probing.NewPinger(host)
	if err != nil {
		return &Result{}, err
	}
	// Default configurations
	pinger.Timeout = DefaultTimeoutMs
	pinger.Interval = DefaultIntervalMs
	pinger.Count = DefaultCount
	pinger.SetPrivileged(cfg.UseRawSocket)
	if cfg.Timeout > 0 {
		pinger.Timeout = cfg.Timeout
	}
	if cfg.Delay > 0 {
		pinger.Interval = cfg.Delay
	}
	if cfg.Count > 0 {
		pinger.Count = cfg.Count
	}
	err = pinger.Run() // Blocks until finished.
	if err != nil {
		return &Result{}, err
	}
	stats := pinger.Statistics() // get send/receive/duplicate/rtt stats

	log.Tracef("ping stats: %+v", stats)

	return &Result{
		PacketsReceived:           stats.PacketsRecv,
		PacketsSent:               stats.PacketsSent,
		PacketsReceivedDuplicates: stats.PacketsRecvDuplicates,
		Rtts:                      convertRttsAsFloat(stats.Rtts),
	}, nil
}

func convertRttsAsFloat(rtts []time.Duration) []float64 {
	rttsFloat := make([]float64, 0, len(rtts))
	for _, rtt := range rtts {
		rttsFloat = append(rttsFloat, rtt.Seconds()/1000)
	}
	return rttsFloat
}

func computeJitter(rtts []time.Duration) time.Duration {
	if len(rtts) < 2 {
		return time.Duration(0)
	}
	var prevRtt time.Duration
	var cumulativeDifference time.Duration
	for _, rtt := range rtts {
		if prevRtt != 0 {
			cumulativeDifference += (rtt - prevRtt).Abs()
		}
		prevRtt = rtt
	}
	jitter := cumulativeDifference / time.Duration(len(rtts)-1)
	return jitter
}
