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
	"github.com/DataDog/datadog-traceroute/traceroute"
	"github.com/spf13/cobra"

	"github.com/DataDog/datadog-traceroute/log"
)

type args struct {
	protocol              string
	tracerouteQueries     int
	e2eQueries            int
	maxTTL                int
	timeout               int
	totalTimeoutMs        int
	tcpmethod             string
	port                  int
	wantV6                bool
	reverseDns            bool
	collectSourcePublicIP bool
	verbose               bool
	useWindowsDriver      bool
	skipPrivateHops       bool
}

var Args args

var rootCmd = &cobra.Command{
	Use:   "datadog-traceroute [target]",
	Short: "Multi-protocol datadog traceroute CLI",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if Args.verbose {
			log.SetLogLevel(log.LevelTrace)
		}

		if err := common.ValidateMaxTTL("--max-ttl", Args.maxTTL); err != nil {
			return err
		}
		if err := common.ValidateTimeoutMs("--timeout", Args.timeout, common.MaxTimeoutMs); err != nil {
			return err
		}
		if err := common.ValidateTimeoutMs("--total-timeout-ms", Args.totalTimeoutMs, common.MaxTimeoutMs); err != nil {
			return err
		}

		totalTimeout := time.Duration(Args.totalTimeoutMs) * time.Millisecond
		probeTimeout := common.ResolveProbeTimeout(
			time.Duration(Args.timeout)*time.Millisecond,
			totalTimeout,
			Args.maxTTL,
			cmd.Flags().Changed("timeout"),
		)
		params := traceroute.TracerouteParams{
			Hostname:              args[0],
			Port:                  Args.port,
			Protocol:              Args.protocol,
			MinTTL:                common.DefaultMinTTL,
			MaxTTL:                Args.maxTTL,
			Delay:                 common.DefaultDelay,
			Timeout:               probeTimeout,
			TotalTimeout:          totalTimeout,
			TCPMethod:             traceroute.TCPMethod(Args.tcpmethod),
			WantV6:                Args.wantV6,
			ReverseDns:            Args.reverseDns,
			CollectSourcePublicIP: Args.collectSourcePublicIP,
			TracerouteQueries:     Args.tracerouteQueries,
			E2eQueries:            Args.e2eQueries,
			UseWindowsDriver:      Args.useWindowsDriver,
			SkipPrivateHops:       Args.skipPrivateHops,
		}

		// Start the driver if it's configured to be used.
		if params.UseWindowsDriver {
			err := packets.StartDriver()
			if err != nil {
				return fmt.Errorf("failed to start driver: %w", err)
			}
		}

		tr := traceroute.NewTraceroute()
		results, err := tr.RunTraceroute(cmd.Context(), params)
		if err != nil {
			return fmt.Errorf("failed to run traceroute: %w", err)
		}
		jsonStr, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return fmt.Errorf("JSON marshalling failed: %w", err)
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
	rootCmd.Flags().IntVarP(&Args.maxTTL, "max-ttl", "m", common.DefaultMaxTTL, fmt.Sprintf("Maximum TTL (%d-%d)", common.DefaultMinTTL, common.MaxAllowedTTL))
	rootCmd.Flags().BoolVarP(&Args.verbose, "verbose", "v", false, "verbose")
	rootCmd.Flags().StringVarP(&Args.tcpmethod, "tcp-method", "", common.DefaultTcpMethod, "Method used to run TCP (syn, sack, prefer_sack)")
	rootCmd.Flags().BoolVarP(&Args.wantV6, "ipv6", "", common.DefaultWantV6, "IPv6")
	rootCmd.Flags().IntVarP(&Args.timeout, "timeout", "", common.DefaultNetworkPathTimeout, "Per-probe timeout (ms); when omitted with a total timeout, derived from 90% of its per-hop budget")
	rootCmd.Flags().IntVarP(&Args.totalTimeoutMs, "total-timeout-ms", "", common.DefaultTotalTimeoutMs, "Total timeout for the whole traceroute run (ms). 0 disables the overall deadline")
	rootCmd.Flags().BoolVarP(&Args.reverseDns, "reverse-dns", "", common.DefaultReverseDns, "Enrich IPs with Reverse DNS names")
	rootCmd.Flags().BoolVarP(&Args.collectSourcePublicIP, "source-public-ip", "", common.DefaultCollectSourcePublicIP, "Enrich with Source Public IP")
	rootCmd.Flags().IntVarP(&Args.e2eQueries, "e2e-queries", "Q", common.DefaultNumE2eProbes, "Number of e2e probes queries")
	rootCmd.Flags().BoolVarP(&Args.useWindowsDriver, "windows-driver", "", common.DefaultUseWindowsDriver, "Use Windows driver for traceroute (Windows only)")
	rootCmd.Flags().BoolVarP(&Args.skipPrivateHops, "skip-private-hops", "", common.DefaultSkipPrivateHops, "Skip private hops")
}
