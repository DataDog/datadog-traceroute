package traceroute

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
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

type runTracerouteOnceFnType func(ctx context.Context, params TracerouteParams, destinationPort int) (*result.TracerouteRun, error)

// runTracerouteOnceFn is declared for testing purpose (to be replaced by mock impl during tests)
var runTracerouteOnceFn = runTracerouteOnce

func runTracerouteOnce(ctx context.Context, params TracerouteParams, destinationPort int) (*result.TracerouteRun, error) {
	var trRun *result.TracerouteRun
	switch params.Protocol {
	case "udp":
		target, err := parseTarget(params.Hostname, destinationPort, params.WantV6)
		if err != nil {
			return nil, err
		}
		cfg := udp.NewUDPv4(
			target.Addr().AsSlice(),
			target.Port(),
			uint8(params.MinTTL),
			uint8(params.MaxTTL),
			time.Duration(params.Delay)*time.Millisecond,
			params.Timeout,
			params.UseWindowsDriver)

		trRun, err = cfg.Traceroute()
		if err != nil {
			return nil, fmt.Errorf("could not generate udp traceroute results: %w", err)
		}

	case "tcp":
		target, err := parseTarget(params.Hostname, destinationPort, params.WantV6)
		if err != nil {
			return nil, err
		}

		doSyn := func() (*result.TracerouteRun, error) {
			tr := tcp.NewTCPv4(target.Addr().AsSlice(), target.Port(), uint8(params.MinTTL), uint8(params.MaxTTL), time.Duration(params.Delay)*time.Millisecond, params.Timeout, params.TCPSynParisTracerouteMode, params.UseWindowsDriver)
			return tr.Traceroute()
		}
		doSack := func() (*result.TracerouteRun, error) {
			sackParams, err := makeSackParams(target.Addr().AsSlice(), target.Port(), uint8(params.MinTTL), uint8(params.MaxTTL), params.Timeout, params.UseWindowsDriver)
			if err != nil {
				return nil, fmt.Errorf("failed to make sack params: %w", err)
			}
			return sack.RunSackTraceroute(context.TODO(), sackParams)
		}
		doSynSocket := func() (*result.TracerouteRun, error) {
			tr := tcp.NewTCPv4(target.Addr().AsSlice(), target.Port(), uint8(params.MinTTL), uint8(params.MaxTTL), time.Duration(params.Delay)*time.Millisecond, params.Timeout, params.TCPSynParisTracerouteMode, params.UseWindowsDriver)
			return tr.TracerouteSequentialSocket()
		}

		trRun, err = performTCPFallback(params.TCPMethod, doSyn, doSack, doSynSocket)
		if err != nil {
			return nil, err
		}
	case "icmp":
		target, err := parseTarget(params.Hostname, 80, params.WantV6)
		if err != nil {
			return nil, err
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
			UseWindowsDriver: params.UseWindowsDriver,
		}
		trRun, err = icmp.RunICMPTraceroute(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("could not generate icmp traceroute results: %w", err)
		}
	default:
		return nil, &InvalidTargetError{Err: fmt.Errorf("unknown protocol: %q", params.Protocol)}
	}
	return trRun, nil
}

// runE2eProbeOnce performs an end-to-end probe to the destination without probing intermediate hops.
// It reuses runTracerouteOnce() with modified TTL parameters where MinTTL is set to the same value
// as MaxTTL, essentially sending a single probe to the destination instead of incrementally probing
// each hop along the path, measuring RTT to the destination using the existing traceroute infrastructure.
func runE2eProbeOnce(ctx context.Context, params TracerouteParams, destinationPort int) (float64, error) {
	params.MinTTL = params.MaxTTL

	// Don't use SACK for e2e probes because some servers don't properly reply with SACK responses,
	// even if they respond with the SACK permitted option during the handshake, which can result in
	// e2e probe failures.
	if params.Protocol == "tcp" && (params.TCPMethod == TCPConfigSACK || params.TCPMethod == TCPConfigPreferSACK) {
		params.TCPMethod = TCPConfigSYN
	}

	trRun, err := runTracerouteOnceFn(ctx, params, destinationPort)
	if err != nil {
		return 0, err
	}
	destHop := trRun.GetDestinationHop()
	if destHop == nil {
		return 0, nil
	}
	return destHop.RTT, nil
}

func makeSackParams(target net.IP, targetPort uint16, minTTL uint8, maxTTL uint8, timeout time.Duration, useWindowsDriver bool) (sack.Params, error) {
	targetAddr, ok := netip.AddrFromSlice(target)
	if !ok {
		return sack.Params{}, fmt.Errorf("invalid target IP")
	}
	parallelParams := common.TracerouteParallelParams{
		TracerouteParams: common.TracerouteParams{
			MinTTL:            minTTL,
			MaxTTL:            maxTTL,
			TracerouteTimeout: timeout,
			PollFrequency:     100 * time.Millisecond,
			SendDelay:         10 * time.Millisecond,
		},
	}
	params := sack.Params{
		Target:           netip.AddrPortFrom(targetAddr, targetPort),
		HandshakeTimeout: timeout,
		FinTimeout:       500 * time.Second,
		ParallelParams:   parallelParams,
		LoosenICMPSrc:    true,
		UseWindowsDriver: useWindowsDriver,
	}
	return params, nil
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
		return netip.AddrPort{}, &InvalidTargetError{Err: fmt.Errorf("invalid address: %w", err)}
	}

	ip, err := netip.ParseAddr(host)
	if err != nil {
		// Not an IP — do DNS resolution
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return netip.AddrPort{}, &DNSError{Host: host, Err: err}
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
			family := "IPv4"
			if wantIPv6 {
				family = "IPv6"
			}
			return netip.AddrPort{}, &DNSError{Host: host, Err: fmt.Errorf("no %s address found", family)}
		}
		if !ip.IsValid() {
			ip = netip.MustParseAddr(ips[0].String())
		}
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return netip.AddrPort{}, &InvalidTargetError{Err: fmt.Errorf("invalid port: %v", portStr)}
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

type tracerouteImpl func() (*result.TracerouteRun, error)

func performTCPFallback(tcpMethod TCPMethod, doSyn, doSack, doSynSocket tracerouteImpl) (*result.TracerouteRun, error) {
	if tcpMethod == "" {
		tcpMethod = "syn"
	}
	switch tcpMethod {
	case TCPConfigSYN:
		return doSyn()
	case TCPConfigSACK:
		return doSack()
	case TCPConfigSYNSocket:
		return doSynSocket()
	case TCPConfigPreferSACK:
		results, err := doSack()
		var sackNotSupportedErr *sack.NotSupportedError
		if errors.As(err, &sackNotSupportedErr) {
			return doSyn()
		}
		if err != nil {
			return nil, fmt.Errorf("SACK traceroute failed fatally, not falling back: %w", err)
		}
		return results, nil
	default:
		return nil, fmt.Errorf("unexpected TCPMethod: %s", tcpMethod)
	}
}
