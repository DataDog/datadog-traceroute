package reversedns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/DataDog/datadog-traceroute/log"
)

const reverseDnsDefaultTimeout = 5 * time.Second

// LookupAddrFn is defined as variable to ease testing
var LookupAddrFn = net.DefaultResolver.LookupAddr

// GetReverseDnsForIP returns the reverse DNS for the given IP address as a net.IP.
func GetReverseDnsForIP(ipAddress net.IP) ([]string, error) {
	if len(ipAddress) == 0 {
		return nil, errors.New("invalid nil IP address")
	}
	return GetReverseDns(ipAddress.String())
}

// GetReverseDnsForIPs returns the reverse DNS for the given IPs addresses.
func GetReverseDnsForIPs(ips []net.IP) (map[string][]string, error) {
	var outputIPs = make(map[string][]string)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, ip := range ips {
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			destRDns, err := GetReverseDnsForIP(ip)
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

// GetReverseDns returns the hostname for the given IP address as a string.
func GetReverseDns(ipAddr string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), reverseDnsDefaultTimeout)
	defer cancel()
	rawReverseDnsNames, err := LookupAddrFn(ctx, ipAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get reverse dns: %w", err)
	}

	return rawReverseDnsNames, nil
}
