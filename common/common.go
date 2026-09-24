// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package common contains common functionality for both TCP and UDP
// traceroute implementations
package common

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"time"

	"golang.org/x/net/ipv4"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	DefaultNetworkPathTimeout = 3000
	DefaultTotalTimeoutMs     = 0 // 0 means no overall run timeout is enforced

	// DefaultProbePollFrequency is the precision with which polling drivers observe
	// cancellation and TotalTimeout. ReceiveProbe is a blocking API, so a call already
	// in progress can return up to one poll interval (100 ms) after the context deadline.
	// We intentionally accept that bounded error instead of adding per-driver deadline
	// clamping and coordination complexity to make the overall deadline exact.
	DefaultProbePollFrequency = 100 * time.Millisecond

	// MinProbeTimeout is the smallest per-probe timeout ResolveProbeTimeout will
	// derive from TotalTimeout. Without a floor, a large MaxTTL divided into a
	// modest TotalTimeout can derive a probe window too short to ever receive a
	// response, silently guaranteeing every probe times out.
	MinProbeTimeout = 50 * time.Millisecond

	// MaxTimeoutMs is the largest millisecond value that can be converted to a time.Duration
	// (int64 nanoseconds) without overflowing. It's a pure overflow guard, not a business
	// limit: existing CLI/HTTP callers must keep working with whatever timeout they already
	// send, so this is deliberately not an arbitrarily chosen "reasonable" cap.
	MaxTimeoutMs = math.MaxInt64 / int64(time.Millisecond)

	DefaultPort                  = 33434
	DefaultTracerouteQueries     = 3
	DefaultNumE2eProbes          = 50
	DefaultMinTTL                = 1
	DefaultMaxTTL                = 30
	MaxAllowedTTL                = 255 // TTL is represented as uint8 by all traceroute drivers
	DefaultDelay                 = 50  //msec
	DefaultProtocol              = "udp"
	DefaultTcpMethod             = "syn"
	DefaultWantV6                = false
	DefaultReverseDns            = false
	DefaultCollectSourcePublicIP = false
	DefaultUseWindowsDriver      = false
	DefaultSkipPrivateHops       = false
)

type (
	// CanceledError is sent when a listener
	// is canceled
	CanceledError string

	// MismatchError is an error type that indicates a MatcherFunc
	// failed due to one or more fields from the packet not matching
	// the expected information
	MismatchError string

	// MatcherFunc defines functions for matching a packet from the wire to
	// a traceroute based on the source/destination addresses and an identifier
	MatcherFunc func(*ipv4.Header, []byte, net.IP, uint16, net.IP, uint16, uint32, uint16) (net.IP, error)
)

// Error implements the error interface for
// CanceledError
func (c CanceledError) Error() string {
	return string(c)
}

// Error implements the error interface for
// MismatchError
func (m MismatchError) Error() string {
	return string(m)
}

// ValidateTimeoutMs validates a millisecond timeout value supplied by a caller (CLI flag or
// HTTP query parameter). It rejects negative values, which would otherwise silently disable
// a deadline that the documentation says only zero disables, and values exceeding max. Pass
// MaxTimeoutMs as max to only guard against overflowing time.Duration once converted to
// nanoseconds, without imposing any additional business limit. A non-positive max disables
// the upper bound entirely.
func ValidateTimeoutMs(name string, ms int, max int64) error {
	if ms < 0 {
		return fmt.Errorf("%s must not be negative, got %d", name, ms)
	}
	if max > 0 && int64(ms) > max {
		return fmt.Errorf("%s must not exceed %d, got %d", name, max, ms)
	}
	return nil
}

// ValidateMaxTTL validates MaxTTL before it is converted to the uint8 representation used
// by the packet drivers. Without this check, values above 255 wrap modulo 256 and can cause
// a traceroute to probe a much smaller TTL range than the caller requested.
func ValidateMaxTTL(name string, maxTTL int) error {
	if maxTTL < DefaultMinTTL || maxTTL > MaxAllowedTTL {
		return fmt.Errorf("%s must be between %d and %d, got %d", name, DefaultMinTTL, MaxAllowedTTL, maxTTL)
	}
	return nil
}

// ValidateQueryCount rejects negative query counts before they are used to size
// result slices. Zero is valid and disables that query type.
func ValidateQueryCount(name string, count int) error {
	if count < 0 {
		return fmt.Errorf("%s must not be negative, got %d", name, count)
	}
	return nil
}

// ValidatePort rejects destination port values outside the valid TCP/UDP port range.
// port == 0 is allowed through since callers treat it as "use the default port".
func ValidatePort(name string, port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("%s must be between 0 and 65535, got %d", name, port)
	}
	return nil
}

// ResolveProbeTimeout returns a positive explicitly configured per-probe timeout.
// A non-positive timeout is treated as unset. When no timeout was configured and
// an overall timeout is available, it reserves 10% of the per-hop budget for work
// outside probe waits. The result is floored at MinProbeTimeout so a large probeCount
// can't derive an unusably short window. If there is no overall timeout, it preserves
// the supplied legacy default or falls back to DefaultNetworkPathTimeout.
//
// probeCount is the number of TTLs actually probed (MaxTTL - MinTTL + 1), not MaxTTL
// itself: a narrow TTL range (e.g. MinTTL=250, MaxTTL=255) sends far fewer probes than
// MaxTTL would suggest, and budgeting per MaxTTL alone would derive an unnecessarily
// short per-probe window.
func ResolveProbeTimeout(configuredTimeout, totalTimeout time.Duration, probeCount int, configured bool) time.Duration {
	if configured && configuredTimeout > 0 {
		return configuredTimeout
	}
	if totalTimeout <= 0 || probeCount < 1 || probeCount > MaxAllowedTTL {
		if configuredTimeout > 0 {
			return configuredTimeout
		}
		return time.Duration(DefaultNetworkPathTimeout) * time.Millisecond
	}

	// Calculate totalTimeout * 9 / (probeCount * 10) without overflowing when
	// totalTimeout is close to time.Duration's upper bound.
	divisor := time.Duration(probeCount) * 10
	quotient := totalTimeout / divisor
	remainder := totalTimeout % divisor
	derived := quotient*9 + remainder*9/divisor
	if derived < MinProbeTimeout {
		return MinProbeTimeout
	}
	return derived
}

// contextWithOptionalTimeout applies timeout when it is positive. A zero timeout means
// no local deadline, deferring to the parent context's TotalTimeout or cancellation.
// If the parent context has no deadline of its own either, that would leave the call
// completely unbounded, so a legacy default is applied as a last-resort safety net.
func contextWithOptionalTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout > 0 {
		return context.WithTimeout(ctx, timeout)
	}
	if _, ok := ctx.Deadline(); !ok {
		return context.WithTimeout(ctx, time.Duration(DefaultNetworkPathTimeout)*time.Millisecond)
	}
	return context.WithCancel(ctx)
}

// LocalAddrForHost takes in a destination IP and port and returns the local
// address that should be used to connect to the destination. The returned connection
// should be closed by the caller when the local UDP port is no longer needed
func LocalAddrForHost(destIP net.IP, destPort uint16) (*net.UDPAddr, net.Conn, error) {
	// this is a quick way to get the local address for connecting to the host
	// using UDP as the network type to avoid actually creating a connection to
	// the host, just get the OS to give us a local IP and local ephemeral port
	conn, err := net.Dial("udp", net.JoinHostPort(destIP.String(), strconv.Itoa(int(destPort))))
	if err != nil {
		return nil, nil, err
	}
	localAddr := conn.LocalAddr()

	localUDPAddr, ok := localAddr.(*net.UDPAddr)
	if !ok {
		return nil, nil, fmt.Errorf("invalid address type for %s: want %T, got %T", localAddr, localUDPAddr, localAddr)
	}

	// On macOS, net.Dial() to a loopback destination may return a non-loopback local address.
	// Force the source to be a loopback address so packets can be properly routed.
	if destIP.IsLoopback() && !localUDPAddr.IP.IsLoopback() {
		if destIP.To4() != nil {
			localUDPAddr.IP = net.IPv4(127, 0, 0, 1)
		} else {
			localUDPAddr.IP = net.IPv6loopback
		}
	}

	return localUDPAddr, conn, nil
}

// UnmappedAddrFromSlice is the same as netip.AddrFromSlice but it also gets rid of mapped ipv6 addresses.
func UnmappedAddrFromSlice(slice []byte) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(slice)
	return addr.Unmap(), ok
}

// IPFamily returns the IP family of an address (v4 or v6) as a gopacket layer
func IPFamily(addr netip.Addr) gopacket.LayerType {
	if addr.Is4() {
		return layers.LayerTypeIPv4
	}
	return layers.LayerTypeIPv6
}
