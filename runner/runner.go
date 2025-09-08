package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/icmp"
	"github.com/DataDog/datadog-traceroute/result"
	"github.com/DataDog/datadog-traceroute/sack"
	"github.com/DataDog/datadog-traceroute/tcp"
	"github.com/DataDog/datadog-traceroute/traceroute"
	"github.com/DataDog/datadog-traceroute/udp"
)

func RunTraceroute(ctx context.Context, params TracerouteParams) (*result.Results, error) {
	destinationPort := params.Port
	if destinationPort == 0 {
		destinationPort = common.DefaultPort
	}

	results, err := runTracerouteMulti(ctx, params, destinationPort)
	if err != nil {
		return nil, err
	}

	results.Params = result.Params{
		Protocol: params.Protocol,
		Hostname: params.Hostname,
		Port:     destinationPort,
	}
	if params.ReverseDns {
		results.EnrichWithReverseDns()
	}
	results.Normalize()
	return results, nil
}

func runTracerouteMulti(ctx context.Context, params TracerouteParams, destinationPort int) (*result.Results, error) {
	var wg sync.WaitGroup
	var results result.Results
	var multiErr []error
	mu := &sync.Mutex{}
	for i := 0; i < params.TracerouteQueries; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			oneResult, err := runTracerouteOnce(ctx, params, destinationPort)
			mu.Lock()
			if err != nil {
				multiErr = append(multiErr, err)
			} else {
				results.Traceroute.Runs = append(results.Traceroute.Runs, oneResult.Traceroute.Runs...)
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(multiErr) > 0 {
		return nil, errors.Join(multiErr...)
	}
	fmt.Println(results)
	return &results, nil
}
func runTracerouteOnce(ctx context.Context, params TracerouteParams, destinationPort int) (*result.Results, error) {
	var results *result.Results
	switch params.Protocol {
	case "udp":
		target, err := parseTarget(params.Hostname, destinationPort, params.WantV6)
		if err != nil {
			return nil, fmt.Errorf("invalid target: %w", err)
		}
		cfg := udp.NewUDPv4(
			target.Addr().AsSlice(),
			target.Port(),
			uint16(params.TracerouteCount),
			uint8(common.DefaultMinTTL),
			uint8(params.MaxTTL),
			time.Duration(params.Delay)*time.Millisecond,
			params.Timeout)

		results, err = cfg.Traceroute()
		if err != nil {
			return nil, fmt.Errorf("could not generate udp traceroute results: %w", err)
		}

	case "tcp":
		target, err := parseTarget(params.Hostname, destinationPort, params.WantV6)
		if err != nil {
			return nil, fmt.Errorf("invalid target: %w", err)
		}

		doSyn := func() (*result.Results, error) {
			tr := tcp.NewTCPv4(target.Addr().AsSlice(), target.Port(), uint16(params.TracerouteCount), uint8(common.DefaultMinTTL), uint8(params.MaxTTL), time.Duration(params.Delay)*time.Millisecond, params.Timeout, params.TCPSynParisTracerouteMode)
			return tr.Traceroute()
		}
		doSack := func() (*result.Results, error) {
			params, err := makeSackParams(target.Addr().AsSlice(), target.Port(), uint8(common.DefaultMinTTL), uint8(params.MaxTTL), params.Timeout)
			if err != nil {
				return nil, fmt.Errorf("failed to make sack params: %w", err)
			}
			return sack.RunSackTraceroute(context.TODO(), params)
		}
		doSynSocket := func() (*result.Results, error) {
			tr := tcp.NewTCPv4(target.Addr().AsSlice(), target.Port(), uint16(params.TracerouteCount), uint8(common.DefaultMinTTL), uint8(params.MaxTTL), time.Duration(params.Delay)*time.Millisecond, params.Timeout, params.TCPSynParisTracerouteMode)
			return tr.TracerouteSequentialSocket()
		}

		results, err = performTCPFallback(params.TCPMethod, doSyn, doSack, doSynSocket)
		if err != nil {
			return nil, err
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
					MinTTL:            uint8(common.DefaultMinTTL),
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
	return results, nil
}

func makeSackParams(target net.IP, targetPort uint16, minTTL uint8, maxTTL uint8, timeout time.Duration) (sack.Params, error) {
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

type tracerouteImpl func() (*result.Results, error)

func performTCPFallback(tcpMethod traceroute.TCPMethod, doSyn, doSack, doSynSocket tracerouteImpl) (*result.Results, error) {
	if tcpMethod == "" {
		tcpMethod = "syn"
	}
	switch tcpMethod {
	case traceroute.TCPConfigSYN:
		return doSyn()
	case traceroute.TCPConfigSACK:
		return doSack()
	case traceroute.TCPConfigSYNSocket:
		return doSynSocket()
	case traceroute.TCPConfigPreferSACK:
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
