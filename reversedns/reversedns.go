package reversedns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/DataDog/datadog-traceroute/cache"
	"github.com/DataDog/datadog-traceroute/log"
)

const reverseDnsDefaultTimeout = 5 * time.Second
const reverseDnsCacheTLL = 1 * time.Hour

// LookupAddrFn is defined as variable to ease testing
var LookupAddrFn = net.DefaultResolver.LookupAddr

// GetReverseDnsForIP returns the reverse DNS for the given IP address as a net.IP,
// with no deadline of its own. Prefer GetReverseDnsForIPContext when the caller
// wants the lookup bounded by a context deadline.
func GetReverseDnsForIP(ipAddress net.IP) ([]string, error) {
	return GetReverseDnsForIPContext(context.Background(), ipAddress)
}

// GetReverseDnsForIPContext is the context-aware variant of GetReverseDnsForIP.
func GetReverseDnsForIPContext(ctx context.Context, ipAddress net.IP) ([]string, error) {
	if len(ipAddress) == 0 {
		return nil, errors.New("invalid nil IP address")
	}
	return GetReverseDnsContext(ctx, ipAddress.String())
}

// GetReverseDnsForIPs returns the reverse DNS for the given IPs addresses, with no
// deadline of its own. Prefer GetReverseDnsForIPsContext when the caller wants the
// lookups bounded by a context deadline.
func GetReverseDnsForIPs(ips []net.IP) (map[string][]string, error) {
	return GetReverseDnsForIPsContext(context.Background(), ips)
}

// GetReverseDnsForIPsContext is the context-aware variant of GetReverseDnsForIPs.
func GetReverseDnsForIPsContext(ctx context.Context, ips []net.IP) (map[string][]string, error) {
	var outputIPs = make(map[string][]string)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, ip := range ips {
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			destRDns, err := GetReverseDnsForIPContext(ctx, ip)
			if err != nil {
				log.Debugf("failed to get reverse dns for IP %s: %s", ip, err)
			} else {
				mu.Lock()
				outputIPs[string(ip)] = destRDns
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return outputIPs, nil
}

// GetReverseDns returns the hostname for the given IP address as a string, with no
// deadline of its own beyond the fixed per-lookup safety timeout. Prefer
// GetReverseDnsContext when the caller wants the lookup bounded by a context deadline.
func GetReverseDns(ipAddr string) ([]string, error) {
	return GetReverseDnsContext(context.Background(), ipAddr)
}

// GetReverseDnsContext returns the hostname for the given IP address as a string.
// The lookup is bounded by both ctx and a fixed per-lookup safety timeout,
// whichever elapses first.
func GetReverseDnsContext(ctx context.Context, ipAddr string) ([]string, error) {
	resultDns, err := cache.GetWithExpiration("reverse-dns-"+ipAddr, func() ([]string, error) {
		lookupCtx, cancel := context.WithTimeout(ctx, reverseDnsDefaultTimeout)
		defer cancel()
		rawReverseDnsNames, err := LookupAddrFn(lookupCtx, ipAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to get reverse dns: %w", err)
		}
		return rawReverseDnsNames, nil
	}, reverseDnsCacheTLL)
	if err != nil {
		return nil, err
	}
	return resultDns, nil
}
