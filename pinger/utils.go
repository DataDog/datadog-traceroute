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
		CanConnect:                stats.PacketsRecv > 0,
		PacketsReceived:           stats.PacketsRecv,
		PacketsSent:               stats.PacketsSent,
		PacketsReceivedDuplicates: stats.PacketsRecvDuplicates,
		PacketLoss:                stats.PacketLoss,
		RttMin:                    stats.MinRtt.Seconds(),
		RttMax:                    stats.MaxRtt.Seconds(),
		RttAvg:                    stats.AvgRtt.Seconds(),
		RttStdDev:                 computeJitter(stats.Rtts).Seconds(),
	}, nil
}

func computeJitter(rtts []time.Duration) time.Duration {
	log.Tracef("rtts: %+v", rtts)
	if len(rtts) < 2 {
		return time.Duration(0)
	}
	var prevRtt time.Duration
	var cumulativeDifference time.Duration
	for _, rtt := range rtts {
		log.Tracef("prevRtt: %+v , rtt: %+v", prevRtt, rtt)
		log.Tracef("cumulativeDifference: %+v", cumulativeDifference)
		if prevRtt != 0 {
			cumulativeDifference += (rtt - prevRtt).Abs()
		}
		prevRtt = rtt
	}
	log.Tracef("cumulativeDifference: %+v", cumulativeDifference)
	log.Tracef("time.Duration(len(rtts)-1): %+v", time.Duration(len(rtts)-1))
	log.Tracef("len(rtts): %+v", len(rtts))
	return cumulativeDifference / time.Duration(len(rtts)-1)
}
