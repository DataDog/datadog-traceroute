// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package traceroute adds traceroute functionality to the agent
package main

import (
	"fmt"
	"os"

	"github.com/DataDog/datadog-traceroute/cmd"
	"github.com/DataDog/datadog-traceroute/packets"
)

func main() {
	err := packets.StartDriver()
	if err != nil {
		fmt.Printf("Error starting driver: %s\n", err)
		os.Exit(1)
	}
	cmd.Execute()
}
