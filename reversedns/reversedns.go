package reversedns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
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
