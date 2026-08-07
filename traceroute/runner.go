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
	probeTimeout := effectiveProbeTimeout(params)

	var trRun *result.TracerouteRun
	switch params.Protocol {
	case "udp":
		target, err := parseTarget(ctx, params.Hostname, destinationPort, params.WantV6)
		if err != nil {
			return nil, err
		}
		cfg := udp.NewUDPv4(
			target.Addr().AsSlice(),
			target.Port(),
			uint8(params.MinTTL),
			uint8(params.MaxTTL),
			time.Duration(params.Delay)*time.Millisecond,
			probeTimeout,
			params.UseWindowsDriver)

		trRun, err = cfg.TracerouteContext(ctx)
		if err != nil {
			return nil, fmt.Errorf("could not generate udp traceroute results: %w", err)
		}

	case "tcp":
		target, err := parseTarget(ctx, params.Hostname, destinationPort, params.WantV6)
		if err != nil {
			return nil, err
		}

		doSyn := func() (*result.TracerouteRun, error) {
			tr := tcp.NewTCPv4(target.Addr().AsSlice(), target.Port(), uint8(params.MinTTL), uint8(params.MaxTTL), time.Duration(params.Delay)*time.Millisecond, probeTimeout, params.TCPSynParisTracerouteMode, params.UseWindowsDriver)
			return tr.TracerouteContext(ctx)
		}
		doSack := func() (*result.TracerouteRun, error) {
			sackParams, err := makeSackParams(target.Addr().AsSlice(), target.Port(), uint8(params.MinTTL), uint8(params.MaxTTL), probeTimeout, params.UseWindowsDriver)
			if err != nil {
				return nil, fmt.Errorf("failed to make sack params: %w", err)
			}
			return sack.RunSackTraceroute(ctx, sackParams)
		}
		doSynSocket := func() (*result.TracerouteRun, error) {
			tr := tcp.NewTCPv4(target.Addr().AsSlice(), target.Port(), uint8(params.MinTTL), uint8(params.MaxTTL), time.Duration(params.Delay)*time.Millisecond, probeTimeout, params.TCPSynParisTracerouteMode, params.UseWindowsDriver)
			return tr.TracerouteSequentialSocketContext(ctx)
		}

		trRun, err = performTCPFallback(ctx, params.TCPMethod, doSyn, doSack, doSynSocket)
		if err != nil {
			return nil, err
		}
	case "icmp":
		target, err := parseTarget(ctx, params.Hostname, 80, params.WantV6)
		if err != nil {
			return nil, err
		}
		cfg := icmp.Params{
			Target: target.Addr(),
			ParallelParams: common.TracerouteParallelParams{
				TracerouteParams: common.TracerouteParams{
					MinTTL:            uint8(params.MinTTL),
					MaxTTL:            uint8(params.MaxTTL),
					TracerouteTimeout: probeTimeout,
					PollFrequency:     common.DefaultProbePollFrequency,
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

const sackSendDelay = 10 * time.Millisecond

// effectiveProbeTimeout returns the configured per-probe timeout, or derives one
// from TotalTimeout and the TTL range when it is unset. Without a total timeout, it
// uses the legacy default so a silent probe never waits indefinitely.
func effectiveProbeTimeout(params TracerouteParams) time.Duration {
	return common.ResolveProbeTimeout(
		params.Timeout,
		params.TotalTimeout,
		probeCount(params.MinTTL, params.MaxTTL),
		time.Duration(params.Delay)*time.Millisecond,
		params.Timeout > 0,
	)
}

// probeCount returns the number of TTLs that will actually be probed. minTTL is
// clamped to the smallest legal TTL when unset (0) so an omitted MinTTL is treated
// as starting from the first hop rather than shrinking the probe count.
func probeCount(minTTL, maxTTL int) int {
	if minTTL < common.DefaultMinTTL {
		minTTL = common.DefaultMinTTL
	}
	if minTTL > maxTTL {
		return 1
	}
	return maxTTL - minTTL + 1
}

// runE2eProbeOnce performs an end-to-end probe to the destination without probing intermediate hops.
// It reuses runTracerouteOnce() with modified TTL parameters where MinTTL is set to the same value
// as MaxTTL, essentially sending a single probe to the destination instead of incrementally probing
// each hop along the path, measuring RTT to the destination using the existing traceroute infrastructure.
//
// interruptedByParent reports whether ctx (as opposed to this call's own per-probe window, or an
// ordinary network error) is what kept the probe from completing. It's determined from the
// configured deadlines before waiting on anything, rather than by comparing this call's error
// against a live read of ctx.Err() afterward, since ctx keeps running concurrently and a read
// taken after the fact can land on either side of a race with ctx's own expiry.
func runE2eProbeOnce(ctx context.Context, params TracerouteParams, destinationPort int) (rtt float64, err error, interruptedByParent bool) {
	// Compute the per-probe timeout from the real MinTTL/MaxTTL range before overriding
	// MinTTL below: probeCount must reflect the full traceroute's hop count so the E2E
	// probe gets the same per-probe window the hop probes use, not a single-probe budget.
	probeTimeout := effectiveProbeTimeout(params)
	params.MinTTL = params.MaxTTL

	// context.WithTimeout collapses into a plain cancellation wrapper around ctx, with no
	// timer of its own, whenever ctx's own deadline is already due no later than ours (see
	// context.WithDeadline). In that case any DeadlineExceeded this call observes can only
	// have come from ctx. Otherwise our timer is independent and, being no later than ctx's
	// own deadline, is guaranteed to fire first, so a DeadlineExceeded here is ours alone.
	ownDeadlineFiresFirst := true
	localDeadline := time.Now().Add(probeTimeout)
	if parentDeadline, ok := ctx.Deadline(); ok && parentDeadline.Before(localDeadline) {
		ownDeadlineFiresFirst = false
	}

	// Bound the entire E2E query, including DNS resolution and socket setup, so every
	// packet gets one complete and consistent per-probe response window.
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	// Don't use SACK for e2e probes because some servers don't properly reply with SACK responses,
	// even if they respond with the SACK permitted option during the handshake, which can result in
	// e2e probe failures.
	if params.Protocol == "tcp" && (params.TCPMethod == TCPConfigSACK || params.TCPMethod == TCPConfigPreferSACK) {
		params.TCPMethod = TCPConfigSYN
	}

	trRun, err := runTracerouteOnceFn(probeCtx, params, destinationPort)
	if err != nil {
		// context.Canceled can only reach here via ctx: probeCtx's own cancel() (deferred
		// above) hasn't run yet, and a timer created by WithTimeout only ever produces
		// DeadlineExceeded on its own.
		interruptedByParent = errors.Is(err, context.Canceled) ||
			(errors.Is(err, context.DeadlineExceeded) && !ownDeadlineFiresFirst)
		return 0, err, interruptedByParent
	}
	destHop := trRun.GetDestinationHop()
	if destHop == nil {
		return 0, nil, false
	}
	return destHop.RTT, nil, false
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
			PollFrequency:     common.DefaultProbePollFrequency,
			SendDelay:         sackSendDelay,
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

func parseTarget(ctx context.Context, raw string, defaultPort int, wantIPv6 bool) (netip.AddrPort, error) {
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
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return netip.AddrPort{}, &DNSError{Host: host, Err: err}
		}
		if len(ips) == 0 {
			return netip.AddrPort{}, &DNSError{Host: host, Err: fmt.Errorf("no addresses found")}
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
		return netip.AddrPort{}, &InvalidTargetError{Err: fmt.Errorf("invalid port: %s", portStr)}
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

func performTCPFallback(ctx context.Context, tcpMethod TCPMethod, doSyn, doSack, doSynSocket tracerouteImpl) (*result.TracerouteRun, error) {
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
			// SACK can fail with NotSupportedError because the run context expired or was
			// canceled mid-handshake, not because the target lacks SACK support. Falling
			// back to a fresh SYN traceroute in that case would open new packet resources
			// under an already-expired context instead of returning the ctx error.
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
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
