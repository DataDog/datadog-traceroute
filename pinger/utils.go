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
func RunPing(cfg *Config, host string) (*PingResult, error) {
	pinger, err := probing.NewPinger(host)
	if err != nil {
		return &PingResult{}, err
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
		return &PingResult{}, err
	}
	stats := pinger.Statistics() // get send/receive/duplicate/rtt stats

	log.Tracef("ping stats: %+v", stats)

	return &PingResult{
		PacketsReceived: stats.PacketsRecv,
		PacketsSent:     stats.PacketsSent,
		Rtts:            convertRttsAsFloat(stats.Rtts),
	}, nil
}

func convertRttsAsFloat(rtts []time.Duration) []float32 {
	rttsFloat := make([]float32, 0, len(rtts))
	for _, rtt := range rtts {
		rttsFloat = append(rttsFloat, float32(rtt.Seconds()*1000))
	}
	return rttsFloat
}
