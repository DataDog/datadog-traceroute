// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/runner"
	"github.com/DataDog/datadog-traceroute/traceroute"
	"github.com/spf13/cobra"

	"github.com/DataDog/datadog-traceroute/log"
)

type args struct {
	protocol     string
	npaths       int
	minTTL       int
	maxTTL       int
	delay        int
	outputFile   string
	outputFormat string
	timeout      int
	tcpmethod    string
	dport        int
	wantV6       bool
	verbose      bool
}

var Args args

var rootCmd = &cobra.Command{
	Use:   "datadog-traceroute [target]",
	Short: "Multi-protocol datadog traceroute CLI",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var timeout time.Duration
		if Args.timeout == 0 {
			timeout = common.DefaultNetworkPathTimeout * time.Millisecond
		} else {
			timeout = time.Duration(Args.timeout) * time.Millisecond
		}

		log.SetVerbose(Args.verbose)

		params := runner.TracerouteParams{
			Hostname:        args[0],
			Protocol:        Args.protocol,
			MinTTL:          Args.minTTL,
			MaxTTL:          Args.maxTTL,
			Delay:           Args.delay,
			Timeout:         timeout,
			TCPMethod:       traceroute.TCPMethod(Args.tcpmethod),
			DestinationPort: Args.dport,
			WantV6:          Args.wantV6,
		}

		results, err := runner.RunTraceroute(cmd.Context(), params)
		if err != nil {
			return err
		}

		switch Args.outputFormat {
		case "json":
			jsonStr, err := json.MarshalIndent(results, "", "  ")
			if err != nil {
				return fmt.Errorf("JSON marshalling failed: %v", err)
			}
			if err := writeOutput(string(jsonStr)); err != nil {
				return fmt.Errorf("failed to write output: %v", err)
			}
		default:
			return fmt.Errorf("unknown output format: %s", Args.outputFormat)
		}
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVarP(&Args.protocol, "protocol", "p", common.DefaultProtocol, "Protocol to use (udp, tcp, icmp)")
	rootCmd.Flags().StringVarP(&Args.tcpmethod, "tcpmethod", "m", common.DefaultTcpMethod, "Method used to run TCP (syn, sack, prefer_sack)")
	rootCmd.Flags().IntVarP(&Args.npaths, "npaths", "n", common.DefaultNumPaths, "Number of paths to probe")
	rootCmd.Flags().IntVarP(&Args.minTTL, "min-ttl", "t", common.DefaultMinTTL, "Minimum TTL")
	rootCmd.Flags().IntVarP(&Args.maxTTL, "max-ttl", "T", common.DefaultMaxTTL, "Maximum TTL")
	rootCmd.Flags().IntVarP(&Args.delay, "delay", "D", common.DefaultDelay, "Delay between packets (ms)")
	rootCmd.Flags().IntVarP(&Args.timeout, "timeout", "x", 0, "Timeout (ms)")
	rootCmd.Flags().IntVarP(&Args.dport, "dport", "d", common.DefaultTraceroutePort, "the base destination port to send packets to")
	rootCmd.Flags().StringVarP(&Args.outputFile, "output-file", "o", "", "Output file name (or '-' for stdout)")
	rootCmd.Flags().StringVarP(&Args.outputFormat, "output-format", "f", common.DefaultOutputFormat, "Output format (json)")
	rootCmd.Flags().BoolVarP(&Args.wantV6, "want-ipv6", "6", false, "Try IPv6")
	rootCmd.Flags().BoolVarP(&Args.verbose, "verbose", "v", false, "verbose")
}

func writeOutput(data string) error {
	if Args.outputFile == "" || Args.outputFile == "-" {
		fmt.Println(data)
		return nil
	} else {
		return os.WriteFile(Args.outputFile, []byte(data), 0644)
	}
}
