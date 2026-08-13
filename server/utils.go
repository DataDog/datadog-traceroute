// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package server

import (
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/traceroute"
)

// parseTracerouteParams extracts and validates query parameters from the HTTP request
func parseTracerouteParams(url *url.URL) (traceroute.TracerouteParams, error) {
	query := url.Query()

	// Required parameter: hostname (target)
	hostname := query.Get("target")
	if hostname == "" {
		return traceroute.TracerouteParams{}, fmt.Errorf("missing required parameter: target")
	}

	// Parse optional parameters with defaults
	protocol := getStringParam(query, "protocol", common.DefaultProtocol)
	port := getIntParam(query, "port", common.DefaultPort)
	if err := common.ValidatePort("port", port); err != nil {
		return traceroute.TracerouteParams{}, err
	}
	tracerouteQueries, err := parseValidatedQueryCountParam(
		query,
		"traceroute-queries",
		common.DefaultTracerouteQueries,
		common.MaxTracerouteQueries,
	)
	if err != nil {
		return traceroute.TracerouteParams{}, err
	}
	maxTTL, err := parseValidatedMaxTTLParam(query, "max-ttl", common.DefaultMaxTTL)
	if err != nil {
		return traceroute.TracerouteParams{}, err
	}
	timeoutMs, err := parseValidatedTimeoutParam(query, "timeout", common.DefaultNetworkPathTimeout, common.MaxTimeoutMs)
	if err != nil {
		return traceroute.TracerouteParams{}, err
	}
	totalTimeoutMs, err := parseValidatedTimeoutParam(query, "total_timeout_ms", common.DefaultTotalTimeoutMs, common.MaxTimeoutMs)
	if err != nil {
		return traceroute.TracerouteParams{}, err
	}
	timeout := common.ResolveProbeTimeout(
		time.Duration(timeoutMs)*time.Millisecond,
		time.Duration(totalTimeoutMs)*time.Millisecond,
		maxTTL,
		query.Has("timeout"),
	)
	tcpMethod := getStringParam(query, "tcp-method", common.DefaultTcpMethod)
	e2eQueries, err := parseValidatedQueryCountParam(
		query,
		"e2e-queries",
		common.DefaultNumE2eProbes,
		common.MaxE2eQueries,
	)
	if err != nil {
		return traceroute.TracerouteParams{}, err
	}

	// Parse boolean flags
	wantV6 := getBoolParam(query, "ipv6", common.DefaultWantV6)
	reverseDns := getBoolParam(query, "reverse-dns", common.DefaultReverseDns)
	collectSourcePublicIP := getBoolParam(query, "source-public-ip", common.DefaultCollectSourcePublicIP)
	useWindowsDriver := getBoolParam(query, "windows-driver", common.DefaultUseWindowsDriver)
	skipPrivateHops := getBoolParam(query, "skip-private-hops", common.DefaultSkipPrivateHops)
	returnPartialResults := getBoolParam(query, "return-partial-results", false)

	// Construct traceroute parameters
	params := traceroute.TracerouteParams{
		Hostname:              hostname,
		Port:                  port,
		Protocol:              protocol,
		MinTTL:                common.DefaultMinTTL,
		MaxTTL:                maxTTL,
		Delay:                 common.DefaultDelay,
		Timeout:               timeout,
		TotalTimeout:          time.Duration(totalTimeoutMs) * time.Millisecond,
		ReturnPartialResults:  returnPartialResults,
		TCPMethod:             traceroute.TCPMethod(tcpMethod),
		WantV6:                wantV6,
		ReverseDns:            reverseDns,
		CollectSourcePublicIP: collectSourcePublicIP,
		TracerouteQueries:     tracerouteQueries,
		E2eQueries:            e2eQueries,
		UseWindowsDriver:      useWindowsDriver,
		SkipPrivateHops:       skipPrivateHops,
	}

	return params, nil
}

// Helper functions for parsing query parameters

func getStringParam(query map[string][]string, key string, defaultValue string) string {
	if values, ok := query[key]; ok && len(values) > 0 {
		return values[0]
	}
	return defaultValue
}

func getIntParam(query map[string][]string, key string, defaultValue int) int {
	if values, ok := query[key]; ok && len(values) > 0 {
		if val, err := strconv.Atoi(values[0]); err == nil {
			return val
		}
	}
	return defaultValue
}

// parseValidatedMaxTTLParam parses and validates the maximum TTL before it reaches the
// uint8-based packet drivers. Only an absent key gets the default; malformed and
// out-of-range explicit values are rejected.
func parseValidatedMaxTTLParam(query map[string][]string, key string, defaultValue int) (int, error) {
	values, ok := query[key]
	if !ok || len(values) == 0 {
		return defaultValue, nil
	}
	val, err := strconv.Atoi(values[0])
	if err != nil {
		return 0, fmt.Errorf("invalid value for %q: %q is not a valid integer", key, values[0])
	}
	if err := common.ValidateMaxTTL(key, val); err != nil {
		return 0, err
	}
	return val, nil
}

func parseValidatedQueryCountParam(query map[string][]string, key string, defaultValue, max int) (int, error) {
	values, ok := query[key]
	if !ok || len(values) == 0 {
		return defaultValue, nil
	}
	val, err := strconv.Atoi(values[0])
	if err != nil {
		return 0, fmt.Errorf("invalid value for %q: %q is not a valid integer", key, values[0])
	}
	if err := common.ValidateQueryCount(key, val, max); err != nil {
		return 0, err
	}
	return val, nil
}

// parseValidatedTimeoutParam parses a millisecond timeout query parameter, returning
// defaultValue only when the key is entirely absent from the query string, and an error if
// the value is malformed (including an explicitly empty value, e.g. "?total_timeout_ms="),
// negative, or exceeds max. Unlike getIntParam, malformed input is rejected rather than
// silently replaced with the default, since a silent fallback to zero here would disable a
// deadline the documentation says only an explicit zero disables.
func parseValidatedTimeoutParam(query map[string][]string, key string, defaultValue int, max int64) (int, error) {
	values, ok := query[key]
	if !ok || len(values) == 0 {
		return defaultValue, nil
	}
	val, err := strconv.Atoi(values[0])
	if err != nil {
		return 0, fmt.Errorf("invalid value for %q: %q is not a valid integer", key, values[0])
	}
	if err := common.ValidateTimeoutMs(key, val, max); err != nil {
		return 0, err
	}
	return val, nil
}

func getBoolParam(query map[string][]string, key string, defaultValue bool) bool {
	if values, ok := query[key]; ok && len(values) > 0 {
		if val, err := strconv.ParseBool(values[0]); err == nil {
			return val
		}
	}
	return defaultValue
}
