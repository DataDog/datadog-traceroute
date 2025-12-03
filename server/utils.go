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
	tracerouteQueries := getIntParam(query, "traceroute-queries", common.DefaultTracerouteQueries)
	maxTTL := getIntParam(query, "max-ttl", common.DefaultMaxTTL)
	timeoutMs := getIntParam(query, "timeout", int(common.DefaultNetworkPathTimeout))
	tcpMethod := getStringParam(query, "tcp-method", common.DefaultTcpMethod)
	e2eQueries := getIntParam(query, "e2e-queries", common.DefaultNumE2eProbes)

	// Parse boolean flags
	wantV6 := getBoolParam(query, "ipv6", common.DefaultWantV6)
	reverseDns := getBoolParam(query, "reverse-dns", common.DefaultReverseDns)
	collectSourcePublicIP := getBoolParam(query, "source-public-ip", common.DefaultCollectSourcePublicIP)
	useWindowsDriver := getBoolParam(query, "windows-driver", common.DefaultUseWindowsDriver)
	skipPrivateHops := getBoolParam(query, "skip-private-hops", common.DefaultSkipPrivateHops)

	// Construct traceroute parameters
	params := traceroute.TracerouteParams{
		Hostname:              hostname,
		Port:                  port,
		Protocol:              protocol,
		MinTTL:                common.DefaultMinTTL,
		MaxTTL:                maxTTL,
		Delay:                 common.DefaultDelay,
		Timeout:               time.Duration(timeoutMs) * time.Millisecond,
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

func getBoolParam(query map[string][]string, key string, defaultValue bool) bool {
	if values, ok := query[key]; ok && len(values) > 0 {
		if val, err := strconv.ParseBool(values[0]); err == nil {
			return val
		}
	}
	return defaultValue
}
