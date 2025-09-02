package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
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
			results, err = doSyn(target, params)
			if err != nil {
				return nil, fmt.Errorf("could not generate tcp syn traceroute results: %w", err)
			}
		case "sack":
			results, err = doSack(ctx, target, params)
			if err != nil {
				return nil, fmt.Errorf("could not generate tcp sack traceroute results: %w", err)
			}
		case "prefer_sack":
			results, err = doSack(ctx, target, params)
			var sackNotSupportedErr *sack.NotSupportedError
			if errors.As(err, &sackNotSupportedErr) {
				results, err = doSyn(target, params)
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

func doSack(ctx context.Context, target netip.AddrPort, params TracerouteParams) (*result.Results, error) {
	cfg := sack.Params{
		Target:           target,
		HandshakeTimeout: params.Timeout,
		FinTimeout:       500 * time.Second,
		ParallelParams: common.TracerouteParallelParams{
			TracerouteParams: common.TracerouteParams{
				MinTTL:            uint8(params.MinTTL),
				MaxTTL:            uint8(params.MaxTTL),
				TracerouteTimeout: params.Timeout,
				PollFrequency:     100 * time.Millisecond,
				SendDelay:         time.Duration(params.Delay) * time.Millisecond,
			},
		},
		LoosenICMPSrc: true,
	}
	return sack.RunSackTraceroute(ctx, cfg)
}

func doSyn(target netip.AddrPort, params TracerouteParams) (*result.Results, error) {
	compatibilityMode := os.Getenv("COMPAT") == "true"

	cfg := tcp.NewTCPv4(
		target.Addr().AsSlice(),
		target.Port(),
		uint16(params.TracerouteCount),
		uint8(params.MinTTL),
		uint8(params.MaxTTL),
		time.Duration(params.Delay)*time.Millisecond,
		params.Timeout,
		compatibilityMode)

	return cfg.Traceroute()
}

func parseTarget(raw string, defaultPort int, wantIPv6 bool) (netip.AddrPort, error) {
	var host, portStr string
	var err error

	if !hasPort(raw) {
		portStr = strconv.Itoa(defaultPort)
		unwrappedHost := strings.Trim(raw, "[]")
		raw = net.JoinHostPort(unwrappedHost, portStr)
	}

	host, portStr, err = net.SplitHostPort(raw)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid address: %w", err)
	}

	ip, err := netip.ParseAddr(host)
	if err != nil {
		// Not an IP — do DNS resolution
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return netip.AddrPort{}, fmt.Errorf("failed to resolve host %q: %w", host, err)
		}

		found := false
		for _, r := range ips {
			if wantIPv6 {
				if r.To16() != nil {
					ip = netip.MustParseAddr(r.String())
					found = true
					break
				}
			} else {
				if r.To4() != nil {
					ip = netip.MustParseAddr(r.String())
					found = true
					break
				}
			}
		}
		if !found {
			return netip.AddrPort{}, fmt.Errorf("failed to resolve host %q: %w", host, err)
		}
		if !ip.IsValid() {
			ip = netip.MustParseAddr(ips[0].String())
		}
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return netip.AddrPort{}, fmt.Errorf("invalid port: %v", portStr)
	}

	return netip.AddrPortFrom(ip, uint16(port)), nil
}

// hasPort returns true if the input string includes a port
func hasPort(s string) bool {
	if strings.HasPrefix(s, "[") {
		return strings.Contains(s, "]:")
	}
	return strings.Count(s, ":") == 1
}
