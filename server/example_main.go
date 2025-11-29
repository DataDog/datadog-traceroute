// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build ignore
// +build ignore

// This is an example showing how to run the traceroute HTTP server
package main

import (
	"log"

	"github.com/DataDog/datadog-traceroute/server"
)

func main() {
	srv := server.NewServer()
	
	// Start the server on port 8080
	addr := ":8080"
	log.Printf("Starting traceroute HTTP server on %s", addr)
	log.Printf("Example usage: curl 'http://localhost:8080/traceroute?target=google.com&protocol=tcp&port=443'")
	
	if err := srv.Start(addr); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

