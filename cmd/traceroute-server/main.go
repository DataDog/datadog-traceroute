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

	ddlog "github.com/DataDog/datadog-traceroute/log"
	"github.com/DataDog/datadog-traceroute/server"
	"github.com/spf13/cobra"
)

// Default port 3765 is used for Remote Traceroute
// https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=3765
const defaultServerPort = 3765

var (
	addr     string
	logLevel string
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

		srv := server.NewServer()

		log.Printf("Starting traceroute HTTP server on %s", addr)
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
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
