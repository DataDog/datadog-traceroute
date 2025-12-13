// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package e2etests contains end-to-end tests for the datadog-traceroute library.
// These tests use the library programmatically to validate functionality across different
// protocols and network conditions.
//
// To run these tests, use the integration build tag:
//
//	go test -tags=integration -v ./e2etests/
//
// Note: These tests require elevated privileges (root/admin) to create raw sockets.
package e2etests
