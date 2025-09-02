package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/icmp"
	"github.com/DataDog/datadog-traceroute/result"
	"github.com/DataDog/datadog-traceroute/sack"
	"github.com/DataDog/datadog-traceroute/tcp"
	"github.com/DataDog/datadog-traceroute/udp"
)

func RunTraceroute(ctx context.Context, params TracerouteParams) (*result.Results, error) {
	var results *result.Results

	switch params.Protocol {
	case "udp":
		target, err := parseTarget(params.Hostname, params.DestinationPort, params.WantV6)
		if err != nil {
			return nil, fmt.Errorf("invalid target: %w", err)
		}
		cfg := udp.NewUDPv4(
			target.Addr().AsSlice(),
			target.Port(),
			uint16(params.TracerouteCount),
			uint8(params.MinTTL),
			uint8(params.MaxTTL),
			time.Duration(params.Delay)*time.Millisecond,
			params.Timeout)

		results, err = cfg.Traceroute()
		if err != nil {
			return nil, fmt.Errorf("could not generate udp traceroute results: %w", err)
		}

	case "tcp":
		target, err := parseTarget(params.Hostname, params.DestinationPort, params.WantV6)
		if err != nil {
			return nil, fmt.Errorf("invalid target: %w", err)
		}
		switch params.TCPMethod {
		case "syn":
			results, err = doSyn(target, params.Timeout)
			if err != nil {
				return nil, fmt.Errorf("could not generate tcp syn traceroute results: %w", err)
			}
		case "sack":
			results, err = doSack(ctx, target, params.Timeout)
			if err != nil {
				return nil, fmt.Errorf("could not generate tcp sack traceroute results: %w", err)
			}
		case "prefer_sack":
			results, err = doSack(ctx, target, params.Timeout)
			var sackNotSupportedErr *sack.NotSupportedError
			if errors.As(err, &sackNotSupportedErr) {
				results, err = doSyn(target, params.Timeout)
			}
			if err != nil {
				return nil, fmt.Errorf("could not generate tcp syn/sack traceroute results: %w", err)
			}
		default:
			return nil, fmt.Errorf("unknown tcp method: %q", params.TCPMethod)
		}
	case "icmp":
		target, err := parseTarget(params.Hostname, 80, params.WantV6)
		if err != nil {
			return nil, fmt.Errorf("invalid target: %w", err)
		}
		cfg := icmp.Params{
			Target: target.Addr(),
			ParallelParams: common.TracerouteParallelParams{
				TracerouteParams: common.TracerouteParams{
					MinTTL:            uint8(params.MinTTL),
					MaxTTL:            uint8(params.MaxTTL),
					TracerouteTimeout: params.Timeout,
					PollFrequency:     100 * time.Millisecond,
					SendDelay:         time.Duration(params.Delay) * time.Millisecond,
				},
			},
		}
		results, err = icmp.RunICMPTraceroute(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("could not generate icmp traceroute results: %w", err)
		}
	default:
		return nil, fmt.Errorf("unknown Protocol: %q", params.Protocol)
	}

	results.Params = result.Params{
		Protocol: params.Protocol,
		Hostname: params.Hostname,
		Port:     params.DestinationPort,
	}
	results.Normalize()
	return results, nil
}

func doSack(ctx context.Context, target netip.AddrPort, timeout time.Duration) (*result.Results, error) {
	cfg := sack.Params{
		Target:           target,
		HandshakeTimeout: timeout,
		FinTimeout:       500 * time.Second,
		ParallelParams: common.TracerouteParallelParams{
			TracerouteParams: common.TracerouteParams{
				MinTTL:            uint8(Args.minTTL),
				MaxTTL:            uint8(Args.maxTTL),
				TracerouteTimeout: timeout,
				PollFrequency:     100 * time.Millisecond,
				SendDelay:         time.Duration(Args.delay) * time.Millisecond,
			},
		},
		LoosenICMPSrc: true,
	}
	return sack.RunSackTraceroute(ctx, cfg)
}

func doSyn(target netip.AddrPort, timeout time.Duration) (*result.Results, error) {
	compatibilityMode := os.Getenv("COMPAT") == "true"

	cfg := tcp.NewTCPv4(
		target.Addr().AsSlice(),
		target.Port(),
		uint16(Args.npaths),
		uint8(Args.minTTL),
		uint8(Args.maxTTL),
		time.Duration(Args.delay)*time.Millisecond,
		timeout,
		compatibilityMode)

	return cfg.Traceroute()
}
