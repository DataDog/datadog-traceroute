// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package main provides the traceroute HTTP server binary
package main

import (
	"flag"
	"log"

	ddlog "github.com/DataDog/datadog-traceroute/log"
	"github.com/DataDog/datadog-traceroute/server"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP server address to listen on")
	logLevel := flag.String("log-level", "info", "Log level (error, warn, info, debug, trace)")
	flag.Parse()

	// Set the log level
	ddlog.SetLogLevel(ddlog.ParseLogLevel(*logLevel))

	srv := server.NewServer()

	log.Printf("Starting traceroute HTTP server on %s", *addr)
	log.Printf("Log level set to: %s", *logLevel)
	log.Printf("Example usage: curl 'http://localhost:8080/traceroute?target=google.com&protocol=tcp&port=443'")

	if err := srv.Start(*addr); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
