// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package main provides the traceroute HTTP server binary
package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	ddlog "github.com/DataDog/datadog-traceroute/log"
	"github.com/DataDog/datadog-traceroute/packets"
	"github.com/DataDog/datadog-traceroute/server"
	"github.com/spf13/cobra"
)

// Default port 3765 is used for Remote Traceroute
// https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=3765
const defaultServerPort = 3765

// The token is read from the environment, never from a flag: command lines are readable by every local user.
const authTokenEnv = "DATADOG_TRACEROUTE_AUTH_TOKEN"

var (
	addr             string
	logLevel         string
	useWindowsDriver bool
	blockedCIDRs     []string
)

var rootCmd = &cobra.Command{
	Use:   "datadog-traceroute-server",
	Short: "Traceroute HTTP server",
	Long:  `HTTP server that provides traceroute functionality via REST API endpoints`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Set the log level
		level, err := ddlog.ParseLogLevel(logLevel)
		if err != nil {
			return err
		}
		ddlog.SetLogLevel(level)

		if useWindowsDriver {
			if err := packets.StartDriver(); err != nil {
				return fmt.Errorf("failed to start driver: %w", err)
			}
			log.Printf("Windows driver initialized")
		}

		blockedPrefixes, err := server.ParseBlockedPrefixes(blockedCIDRs)
		if err != nil {
			return err
		}
		authToken, authTokenSet := os.LookupEnv(authTokenEnv)
		authToken = strings.TrimSpace(authToken)
		if authTokenSet && authToken == "" {
			return fmt.Errorf("%s is set but empty", authTokenEnv)
		}

		srv := server.NewServerWithOptions(server.Options{
			AuthToken:       authToken,
			BlockedPrefixes: blockedPrefixes,
		})

		log.Printf("Starting traceroute HTTP server on %s", addr)
		if authToken != "" {
			log.Printf("Bearer token from %s required on /traceroute", authTokenEnv)
		} else {
			log.Printf("Warning: %s is not set, so anyone who can reach %s can run traceroutes", authTokenEnv, addr)
		}
		if len(blockedPrefixes) > 0 {
			log.Printf("Blocked target ranges: %v", blockedPrefixes)
		}
		log.Printf("Log level set to: %s", logLevel)
		log.Printf("Example usage: curl http://localhost:%d/traceroute?target=google.com&protocol=tcp&port=443", defaultServerPort)

		if err := srv.Start(addr); err != nil {
			return err
		}
		return nil
	},
}

func init() {
	rootCmd.Flags().StringVarP(&addr, "addr", "a", fmt.Sprintf(":%d", defaultServerPort), "HTTP server address to listen on")
	rootCmd.Flags().StringVarP(&logLevel, "log-level", "l", "info", "Log level (error, warn, info, debug, trace)")
	rootCmd.Flags().StringSliceVar(&blockedCIDRs, "blocked-cidrs", nil, "Comma-separated target CIDRs to refuse, e.g. 169.254.0.0/16,::1/128")
	rootCmd.Flags().BoolVar(&useWindowsDriver, "windows-driver", false, "Use Windows driver for traceroute (Windows only)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
