// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package traceroute

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
)

// ErrorCode represents a classifiable error code aligned with synthetics-worker APIFailureCode.
type ErrorCode string

const (
	// ErrCodeDNS indicates a DNS resolution failure.
	ErrCodeDNS ErrorCode = "DNS"
	// ErrCodeTimeout indicates the operation timed out.
	ErrCodeTimeout ErrorCode = "TIMEOUT"
	// ErrCodeConnRefused indicates the target actively refused the connection.
	ErrCodeConnRefused ErrorCode = "CONNREFUSED"
	// ErrCodeHostUnreach indicates the target host is unreachable.
	ErrCodeHostUnreach ErrorCode = "HOSTUNREACH"
	// ErrCodeNetUnreach indicates the target network is unreachable.
	ErrCodeNetUnreach ErrorCode = "NETUNREACH"
	// ErrCodeDenied indicates a permission error or unsupported configuration.
	ErrCodeDenied ErrorCode = "DENIED"
	// ErrCodeInvalidRequest indicates bad parameters from the caller.
	ErrCodeInvalidRequest ErrorCode = "INVALID_REQUEST"
	// ErrCodeUnknown is the catch-all for unclassified errors.
	ErrCodeUnknown ErrorCode = "UNKNOWN"
)

// TracerouteError is a classified error from a traceroute operation.
type TracerouteError struct {
	Code    ErrorCode
	Message string
	Err     error
}

func (e *TracerouteError) Error() string {
	return e.Message
}

func (e *TracerouteError) Unwrap() error {
	return e.Err
}

// ErrorResponse is the JSON body returned on error from the HTTP API.
type ErrorResponse struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

// DNSError is a sentinel wrapper for DNS resolution failures
// so they can be classified at the HTTP boundary.
type DNSError struct {
	Host string
	Err  error
}

func (e *DNSError) Error() string {
	return fmt.Sprintf("failed to resolve host %q: %s", e.Host, e.Err)
}

func (e *DNSError) Unwrap() error {
	return e.Err
}

// InvalidTargetError represents an invalid target specification (bad port, malformed address).
type InvalidTargetError struct {
	Err error
}

func (e *InvalidTargetError) Error() string {
	return fmt.Sprintf("invalid target: %s", e.Err)
}

func (e *InvalidTargetError) Unwrap() error {
	return e.Err
}

// ClassifyError inspects an error chain and returns a TracerouteError with the appropriate code.
func ClassifyError(err error) *TracerouteError {
	if err == nil {
		return nil
	}

	// Check for our own typed errors first
	var dnsErr *DNSError
	if errors.As(err, &dnsErr) {
		return &TracerouteError{Code: ErrCodeDNS, Message: err.Error(), Err: err}
	}

	var invalidTargetErr *InvalidTargetError
	if errors.As(err, &invalidTargetErr) {
		return &TracerouteError{Code: ErrCodeInvalidRequest, Message: err.Error(), Err: err}
	}

	// Check for context errors (timeout / cancellation)
	if errors.Is(err, context.DeadlineExceeded) {
		return &TracerouteError{Code: ErrCodeTimeout, Message: err.Error(), Err: err}
	}
	if errors.Is(err, context.Canceled) {
		return &TracerouteError{Code: ErrCodeTimeout, Message: err.Error(), Err: err}
	}

	// Check for net.DNSError (from standard library DNS resolution)
	var netDNSErr *net.DNSError
	if errors.As(err, &netDNSErr) {
		if netDNSErr.IsTimeout {
			return &TracerouteError{Code: ErrCodeTimeout, Message: err.Error(), Err: err}
		}
		return &TracerouteError{Code: ErrCodeDNS, Message: err.Error(), Err: err}
	}

	// Check for net.OpError with syscall errors
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var sysErr *syscall.Errno
		if errors.As(opErr.Err, &sysErr) {
			return classifySyscallError(*sysErr, err)
		}
		// net.OpError wrapping a timeout
		if opErr.Timeout() {
			return &TracerouteError{Code: ErrCodeTimeout, Message: err.Error(), Err: err}
		}
	}

	// Check for raw syscall.Errno anywhere in the chain
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return classifySyscallError(errno, err)
	}

	return &TracerouteError{Code: ErrCodeUnknown, Message: err.Error(), Err: err}
}

func classifySyscallError(errno syscall.Errno, original error) *TracerouteError {
	switch errno {
	case syscall.ECONNREFUSED:
		return &TracerouteError{Code: ErrCodeConnRefused, Message: original.Error(), Err: original}
	case syscall.EHOSTUNREACH:
		return &TracerouteError{Code: ErrCodeHostUnreach, Message: original.Error(), Err: original}
	case syscall.ENETUNREACH:
		return &TracerouteError{Code: ErrCodeNetUnreach, Message: original.Error(), Err: original}
	case syscall.EACCES, syscall.EPERM:
		return &TracerouteError{Code: ErrCodeDenied, Message: original.Error(), Err: original}
	case syscall.ETIMEDOUT:
		return &TracerouteError{Code: ErrCodeTimeout, Message: original.Error(), Err: original}
	default:
		return &TracerouteError{Code: ErrCodeUnknown, Message: original.Error(), Err: original}
	}
}
