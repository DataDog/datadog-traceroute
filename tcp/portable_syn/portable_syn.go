// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

// Package main contains a portable binary to easily run SYN traceroutes
package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/DataDog/datadog-traceroute/packets"
	"github.com/DataDog/datadog-traceroute/tcp"
)

func main() {
	loglevel := os.Getenv("LOG_LEVEL")
	if loglevel == "" {
		loglevel = "warn"
	}

	if len(os.Args) < 2 {
		println("Usage: portable_syn <target>")
		os.Exit(1)
	}
	target := netip.MustParseAddrPort(os.Args[1])
	compatibilityMode := os.Getenv("COMPAT") == "true"

	cfg := tcp.NewTCPv4(target.Addr().AsSlice(), target.Port(), 1, 1, 30, 10*time.Millisecond, 1*time.Second, compatibilityMode)

	// start the driver outside of the agent
	// this is for the windows driver
	err := packets.StartDriver()
	if err != nil {
		fmt.Printf("Error starting driver: %s\n", err)
		os.Exit(1)
	}

	results, err := cfg.Traceroute()
	if err != nil {
		fmt.Printf("Traceroute failed: %s\n", err)
		os.Exit(1)
	}
	json, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("Error marshalling results: %s\n", err)
		os.Exit(1)
	}
	println(string(json))
}
