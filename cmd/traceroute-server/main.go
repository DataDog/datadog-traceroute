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

// The token is read from the environment or a file, never from a flag value: command lines are readable by every local user.
const authTokenEnv = "DATADOG_TRACEROUTE_AUTH_TOKEN"

var (
	addr             string
	logLevel         string
	useWindowsDriver bool
	authTokenFile    string
)

// loadAuthToken returns the token and where it came from, or an empty token when neither source is set.
func loadAuthToken(filePath string) (string, string, error) {
	envToken, envSet := os.LookupEnv(authTokenEnv)
	if envSet && filePath != "" {
		return "", "", fmt.Errorf("set either %s or --auth-token-file, not both", authTokenEnv)
	}

	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", "", fmt.Errorf("reading --auth-token-file: %w", err)
		}
		token := strings.TrimSpace(string(data))
		if token == "" {
			return "", "", fmt.Errorf("--auth-token-file %s is empty", filePath)
		}
		return token, filePath, nil
	}

	token := strings.TrimSpace(envToken)
	if envSet && token == "" {
		return "", "", fmt.Errorf("%s is set but empty", authTokenEnv)
	}
	return token, authTokenEnv, nil
}

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

		authToken, authTokenSource, err := loadAuthToken(authTokenFile)
		if err != nil {
			return err
		}

		srv := server.NewServerWithOptions(server.Options{AuthToken: authToken})

		log.Printf("Starting traceroute HTTP server on %s", addr)
		if authToken != "" {
			log.Printf("Bearer token from %s required on /traceroute", authTokenSource)
		} else {
			log.Printf("Warning: neither %s nor --auth-token-file is set, so anyone who can reach %s can run traceroutes", authTokenEnv, addr)
		}
		log.Printf("Log level set to: %s", logLevel)
		log.Printf("Example usage: curl http://127.0.0.1:%d/traceroute?target=google.com&protocol=tcp&port=443", defaultServerPort)

		if err := srv.Start(addr); err != nil {
			return err
		}
		return nil
	},
}

func init() {
	rootCmd.Flags().StringVarP(&addr, "addr", "a", fmt.Sprintf("127.0.0.1:%d", defaultServerPort), "HTTP server address to listen on, loopback by default")
	rootCmd.Flags().StringVarP(&logLevel, "log-level", "l", "info", "Log level (error, warn, info, debug, trace)")
	rootCmd.Flags().StringVar(&authTokenFile, "auth-token-file", "", "File holding the bearer token required on /traceroute, instead of "+authTokenEnv)
	rootCmd.Flags().BoolVar(&useWindowsDriver, "windows-driver", false, "Use Windows driver for traceroute (Windows only)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
