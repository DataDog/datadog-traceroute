// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/packets"
	"github.com/DataDog/datadog-traceroute/result"
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
	returnPartialResults  bool
}

type tracerouteRunner interface {
	RunTraceroute(context.Context, traceroute.TracerouteParams) (*result.Results, error)
}

var Args args

var rootCmd = newRootCmd(&Args, func() tracerouteRunner {
	return traceroute.NewTraceroute()
})

func newRootCmd(cfg *args, newRunner func() tracerouteRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "datadog-traceroute [target]",
		Short: "Multi-protocol datadog traceroute CLI",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, positionalArgs []string) error {
			if cfg.verbose {
				log.SetLogLevel(log.LevelTrace)
			}

			if err := common.ValidateMaxTTL("--max-ttl", cfg.maxTTL); err != nil {
				return err
			}
			if err := common.ValidateTimeoutMs("--timeout", cfg.timeout, common.MaxTimeoutMs); err != nil {
				return err
			}
			if err := common.ValidateTimeoutMs("--total-timeout-ms", cfg.totalTimeoutMs, common.MaxTimeoutMs); err != nil {
				return err
			}
			if err := common.ValidateQueryCount("--traceroute-queries", cfg.tracerouteQueries, common.MaxTracerouteQueries); err != nil {
				return err
			}
			if err := common.ValidateQueryCount("--e2e-queries", cfg.e2eQueries, common.MaxE2eQueries); err != nil {
				return err
			}

			totalTimeout := time.Duration(cfg.totalTimeoutMs) * time.Millisecond
			probeTimeout := common.ResolveProbeTimeout(
				time.Duration(cfg.timeout)*time.Millisecond,
				totalTimeout,
				cfg.maxTTL,
				cmd.Flags().Changed("timeout"),
			)
			params := traceroute.TracerouteParams{
				Hostname:              positionalArgs[0],
				Port:                  cfg.port,
				Protocol:              cfg.protocol,
				MinTTL:                common.DefaultMinTTL,
				MaxTTL:                cfg.maxTTL,
				Delay:                 common.DefaultDelay,
				Timeout:               probeTimeout,
				TotalTimeout:          totalTimeout,
				ReturnPartialResults:  cfg.returnPartialResults,
				TCPMethod:             traceroute.TCPMethod(cfg.tcpmethod),
				WantV6:                cfg.wantV6,
				ReverseDns:            cfg.reverseDns,
				CollectSourcePublicIP: cfg.collectSourcePublicIP,
				TracerouteQueries:     cfg.tracerouteQueries,
				E2eQueries:            cfg.e2eQueries,
				UseWindowsDriver:      cfg.useWindowsDriver,
				SkipPrivateHops:       cfg.skipPrivateHops,
			}

			// Start the driver if it's configured to be used.
			if params.UseWindowsDriver {
				err := packets.StartDriver()
				if err != nil {
					return fmt.Errorf("failed to start driver: %w", err)
				}
			}

			results, err := newRunner().RunTraceroute(cmd.Context(), params)
			if err != nil {
				return fmt.Errorf("failed to run traceroute: %w", err)
			}
			jsonStr, err := json.MarshalIndent(results, "", "  ")
			if err != nil {
				return fmt.Errorf("JSON marshalling failed: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(jsonStr))
			return nil
		},
	}

	cmd.Flags().StringVarP(&cfg.protocol, "proto", "P", common.DefaultProtocol, "Protocol to use (udp, tcp, icmp)")
	cmd.Flags().IntVarP(&cfg.port, "port", "p", common.DefaultPort, "Destination port")
	cmd.Flags().IntVarP(&cfg.tracerouteQueries, "traceroute-queries", "q", common.DefaultTracerouteQueries, fmt.Sprintf("Number of traceroute queries (0-%d)", common.MaxTracerouteQueries))
	cmd.Flags().IntVarP(&cfg.maxTTL, "max-ttl", "m", common.DefaultMaxTTL, fmt.Sprintf("Maximum TTL (%d-%d)", common.DefaultMinTTL, common.MaxAllowedTTL))
	cmd.Flags().BoolVarP(&cfg.verbose, "verbose", "v", false, "verbose")
	cmd.Flags().StringVarP(&cfg.tcpmethod, "tcp-method", "", common.DefaultTcpMethod, "Method used to run TCP (syn, sack, prefer_sack)")
	cmd.Flags().BoolVarP(&cfg.wantV6, "ipv6", "", common.DefaultWantV6, "IPv6")
	cmd.Flags().IntVarP(&cfg.timeout, "timeout", "", common.DefaultNetworkPathTimeout, "Per-probe timeout (ms); when omitted or zero with a total timeout, derived from 90% of its per-hop budget")
	cmd.Flags().IntVarP(&cfg.totalTimeoutMs, "total-timeout-ms", "", common.DefaultTotalTimeoutMs, "Total timeout for the whole traceroute run (ms). 0 disables the overall deadline")
	cmd.Flags().BoolVarP(&cfg.reverseDns, "reverse-dns", "", common.DefaultReverseDns, "Enrich IPs with Reverse DNS names")
	cmd.Flags().BoolVarP(&cfg.collectSourcePublicIP, "source-public-ip", "", common.DefaultCollectSourcePublicIP, "Enrich with Source Public IP")
	cmd.Flags().IntVarP(&cfg.e2eQueries, "e2e-queries", "Q", common.DefaultNumE2eProbes, fmt.Sprintf("Number of e2e probe queries (0-%d)", common.MaxE2eQueries))
	cmd.Flags().BoolVarP(&cfg.useWindowsDriver, "windows-driver", "", common.DefaultUseWindowsDriver, "Use Windows driver for traceroute (Windows only)")
	cmd.Flags().BoolVarP(&cfg.skipPrivateHops, "skip-private-hops", "", common.DefaultSkipPrivateHops, "Skip private hops")
	cmd.Flags().BoolVarP(&cfg.returnPartialResults, "return-partial-results", "", false, "Return completed traceroute runs when the total timeout expires")

	return cmd
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
