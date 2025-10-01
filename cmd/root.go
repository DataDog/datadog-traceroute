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
	"github.com/DataDog/datadog-traceroute/packets"
	"github.com/DataDog/datadog-traceroute/runner"
	"github.com/DataDog/datadog-traceroute/traceroute"
	"github.com/spf13/cobra"

	"github.com/DataDog/datadog-traceroute/log"
)

type args struct {
	protocol          string
	tracerouteQueries int
	e2eQueries        int
	maxTTL            int
	timeout           int
	tcpmethod         string
	port              int
	wantV6            bool
	reverseDns        bool
	verbose           bool
	useWindowsDriver  bool
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
			Hostname:          args[0],
			Port:              Args.port,
			Protocol:          Args.protocol,
			MinTTL:            common.DefaultMinTTL,
			MaxTTL:            Args.maxTTL,
			Delay:             common.DefaultDelay,
			Timeout:           timeout,
			TCPMethod:         traceroute.TCPMethod(Args.tcpmethod),
			WantV6:            Args.wantV6,
			ReverseDns:        Args.reverseDns,
			TracerouteQueries: Args.tracerouteQueries,
			E2eQueries:        Args.e2eQueries,
			UseWindowsDriver:  Args.useWindowsDriver,
		}

		// Start the driver if it's configured to be used.
		if params.UseWindowsDriver {
			err := packets.StartDriver()
			if err != nil {
				return fmt.Errorf("failed to start driver: %w", err)
			}
		}

		results, err := runner.RunTraceroute(cmd.Context(), params)
		if err != nil {
			return err
		}
		jsonStr, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return fmt.Errorf("JSON marshalling failed: %v", err)
		}
		fmt.Println(string(jsonStr))
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVarP(&Args.protocol, "proto", "P", common.DefaultProtocol, "Protocol to use (udp, tcp, icmp)")
	rootCmd.Flags().IntVarP(&Args.port, "port", "p", common.DefaultPort, "Destination port")
	rootCmd.Flags().IntVarP(&Args.tracerouteQueries, "traceroute-queries", "q", common.DefaultTracerouteQueries, "Number of traceroute queries")
	rootCmd.Flags().IntVarP(&Args.maxTTL, "max-ttl", "m", common.DefaultMaxTTL, "Maximum TTL")
	rootCmd.Flags().BoolVarP(&Args.verbose, "verbose", "v", false, "verbose")
	rootCmd.Flags().StringVarP(&Args.tcpmethod, "tcp-method", "", common.DefaultTcpMethod, "Method used to run TCP (syn, sack, prefer_sack)")
	rootCmd.Flags().BoolVarP(&Args.wantV6, "ipv6", "", false, "IPv6")
	rootCmd.Flags().IntVarP(&Args.timeout, "timeout", "", 0, "Timeout (ms)")
	rootCmd.Flags().BoolVarP(&Args.reverseDns, "reverse-dns", "", false, "Enrich IPs with Reverse DNS names")
	rootCmd.Flags().IntVarP(&Args.e2eQueries, "e2e-queries", "Q", common.DefaultNumE2eProbes, "Number of e2e probes queries")
	rootCmd.Flags().BoolVarP(&Args.useWindowsDriver, "windows-driver", "", false, "Use Windows driver for traceroute (Windows only)")
}
