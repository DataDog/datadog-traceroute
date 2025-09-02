// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package cmd

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

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

const (
	DefaultNetworkPathTimeout = 3000
	DefaultUDPDestPort        = 33434
	DefaultNumPaths           = 1
	DefaultMinTTL             = 1
	DefaultMaxTTL             = 30
	DefaultDelay              = 50 //msec
	DefaultOutputFormat       = "json"
	DefaultProtocol           = "udp"
	DefaultTcpMethod          = "syn"
)

var Args args

var rootCmd = &cobra.Command{
	Use:   "datadog-traceroute [target]",
	Short: "Multi-Protocol datadog traceroute CLI",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var timeout time.Duration
		if Args.timeout == 0 {
			timeout = DefaultNetworkPathTimeout * time.Millisecond
		} else {
			timeout = time.Duration(Args.timeout) * time.Millisecond
		}

		log.SetVerbose(Args.verbose)

		params := TracerouteParams{
			Hostname:        args[0],
			Protocol:        Args.protocol,
			MinTTL:          Args.minTTL,
			MaxTTL:          Args.maxTTL,
			Delay:           Args.delay,
			Timeout:         timeout,
			TCPMethod:       Args.tcpmethod,
			DestinationPort: Args.dport,
			WantV6:          Args.wantV6,
		}

		results, err := RunTraceroute(cmd.Context(), params)
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
	rootCmd.Flags().StringVarP(&Args.protocol, "protocol", "p", DefaultProtocol, "Protocol to use (udp, tcp, icmp)")
	rootCmd.Flags().StringVarP(&Args.tcpmethod, "tcpmethod", "m", DefaultTcpMethod, "Method used to run TCP (syn, sack, prefer_sack)")
	rootCmd.Flags().IntVarP(&Args.npaths, "npaths", "n", DefaultNumPaths, "Number of paths to probe")
	rootCmd.Flags().IntVarP(&Args.minTTL, "min-ttl", "t", DefaultMinTTL, "Minimum TTL")
	rootCmd.Flags().IntVarP(&Args.maxTTL, "max-ttl", "T", DefaultMaxTTL, "Maximum TTL")
	rootCmd.Flags().IntVarP(&Args.delay, "delay", "D", DefaultDelay, "Delay between packets (ms)")
	rootCmd.Flags().IntVarP(&Args.timeout, "timeout", "x", 0, "Timeout (ms)")
	rootCmd.Flags().IntVarP(&Args.dport, "dport", "d", DefaultUDPDestPort, "the base destination port to send packets to")
	rootCmd.Flags().StringVarP(&Args.outputFile, "output-file", "o", "", "Output file name (or '-' for stdout)")
	rootCmd.Flags().StringVarP(&Args.outputFormat, "output-format", "f", DefaultOutputFormat, "Output format (json)")
	rootCmd.Flags().BoolVarP(&Args.wantV6, "want-ipv6", "6", false, "Try IPv6")
	rootCmd.Flags().BoolVarP(&Args.verbose, "verbose", "v", false, "verbose")
}

func parseTarget(raw string, defaultPort int, wantIPv6 bool) (netip.AddrPort, error) {
	var host, portStr string
	var err error

	if !hasPort(raw) {
		portStr = strconv.Itoa(defaultPort)
		unwrappedHost := strings.Trim(raw, "[]")
		raw = net.JoinHostPort(unwrappedHost, portStr)
	}

	host, portStr, err = net.SplitHostPort(raw)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid address: %w", err)
	}

	ip, err := netip.ParseAddr(host)
	if err != nil {
		// Not an IP — do DNS resolution
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return netip.AddrPort{}, fmt.Errorf("failed to resolve host %q: %w", host, err)
		}

		found := false
		for _, r := range ips {
			if wantIPv6 {
				if r.To16() != nil {
					ip = netip.MustParseAddr(r.String())
					found = true
					break
				}
			} else {
				if r.To4() != nil {
					ip = netip.MustParseAddr(r.String())
					found = true
					break
				}
			}
		}
		if !found {
			return netip.AddrPort{}, fmt.Errorf("failed to resolve host %q: %w", host, err)
		}
		if !ip.IsValid() {
			ip = netip.MustParseAddr(ips[0].String())
		}
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return netip.AddrPort{}, fmt.Errorf("invalid port: %v", portStr)
	}

	return netip.AddrPortFrom(ip, uint16(port)), nil
}

// hasPort returns true if the input string includes a port
func hasPort(s string) bool {
	if strings.HasPrefix(s, "[") {
		return strings.Contains(s, "]:")
	}
	return strings.Count(s, ":") == 1
}

func writeOutput(data string) error {
	if Args.outputFile == "" || Args.outputFile == "-" {
		fmt.Println(data)
		return nil
	} else {
		return os.WriteFile(Args.outputFile, []byte(data), 0644)
	}
}
