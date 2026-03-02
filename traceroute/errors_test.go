package traceroute

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedCode ErrorCode
	}{
		{
			name:         "nil error",
			err:          nil,
			expectedCode: "",
		},
		{
			name:         "DNSError type",
			err:          &DNSError{Host: "bad.host", Err: fmt.Errorf("no such host")},
			expectedCode: ErrCodeDNS,
		},
		{
			name:         "wrapped DNSError",
			err:          fmt.Errorf("traceroute failed: %w", &DNSError{Host: "bad.host", Err: fmt.Errorf("no such host")}),
			expectedCode: ErrCodeDNS,
		},
		{
			name:         "InvalidTargetError",
			err:          &InvalidTargetError{Err: fmt.Errorf("invalid port: abc")},
			expectedCode: ErrCodeInvalidRequest,
		},
		{
			name:         "wrapped InvalidTargetError",
			err:          fmt.Errorf("bad config: %w", &InvalidTargetError{Err: fmt.Errorf("invalid port")}),
			expectedCode: ErrCodeInvalidRequest,
		},
		{
			name:         "context deadline exceeded",
			err:          context.DeadlineExceeded,
			expectedCode: ErrCodeTimeout,
		},
		{
			name:         "wrapped context deadline exceeded",
			err:          fmt.Errorf("operation failed: %w", context.DeadlineExceeded),
			expectedCode: ErrCodeTimeout,
		},
		{
			name:         "context canceled",
			err:          context.Canceled,
			expectedCode: ErrCodeTimeout,
		},
		{
			name: "net.DNSError",
			err: &net.DNSError{
				Err:  "no such host",
				Name: "bad.host",
			},
			expectedCode: ErrCodeDNS,
		},
		{
			name: "net.DNSError timeout",
			err: &net.DNSError{
				Err:       "i/o timeout",
				Name:      "slow.host",
				IsTimeout: true,
			},
			expectedCode: ErrCodeTimeout,
		},
		{
			name: "ECONNREFUSED via net.OpError",
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: &net.AddrError{Err: syscall.ECONNREFUSED.Error()},
			},
			expectedCode: ErrCodeUnknown, // AddrError doesn't wrap syscall.Errno
		},
		{
			name:         "raw ECONNREFUSED",
			err:          syscall.ECONNREFUSED,
			expectedCode: ErrCodeConnRefused,
		},
		{
			name:         "wrapped ECONNREFUSED",
			err:          fmt.Errorf("dial failed: %w", syscall.ECONNREFUSED),
			expectedCode: ErrCodeConnRefused,
		},
		{
			name:         "EHOSTUNREACH",
			err:          syscall.EHOSTUNREACH,
			expectedCode: ErrCodeHostUnreach,
		},
		{
			name:         "ENETUNREACH",
			err:          syscall.ENETUNREACH,
			expectedCode: ErrCodeNetUnreach,
		},
		{
			name:         "EACCES",
			err:          syscall.EACCES,
			expectedCode: ErrCodeDenied,
		},
		{
			name:         "EPERM",
			err:          syscall.EPERM,
			expectedCode: ErrCodeDenied,
		},
		{
			name:         "ETIMEDOUT",
			err:          syscall.ETIMEDOUT,
			expectedCode: ErrCodeTimeout,
		},
		{
			name:         "unknown error",
			err:          errors.New("something went wrong"),
			expectedCode: ErrCodeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyError(tt.err)
			if tt.err == nil {
				assert.Nil(t, result)
				return
			}
			require.NotNil(t, result)
			assert.Equal(t, tt.expectedCode, result.Code)
			assert.NotEmpty(t, result.Message)
		})
	}
}

func TestTracerouteError(t *testing.T) {
	inner := fmt.Errorf("root cause")
	trErr := &TracerouteError{
		Code:    ErrCodeDNS,
		Message: "failed to resolve host",
		Err:     inner,
	}

	assert.Equal(t, "failed to resolve host", trErr.Error())
	assert.ErrorIs(t, trErr, inner)
}

func TestDNSError(t *testing.T) {
	inner := fmt.Errorf("no such host")
	dnsErr := &DNSError{Host: "bad.example.com", Err: inner}

	assert.Contains(t, dnsErr.Error(), "bad.example.com")
	assert.Contains(t, dnsErr.Error(), "no such host")
	assert.ErrorIs(t, dnsErr, inner)
}

func TestInvalidTargetError(t *testing.T) {
	inner := fmt.Errorf("invalid port: abc")
	targetErr := &InvalidTargetError{Err: inner}

	assert.Contains(t, targetErr.Error(), "invalid target")
	assert.Contains(t, targetErr.Error(), "invalid port: abc")
	assert.ErrorIs(t, targetErr, inner)
}

func TestParseTargetErrorTypes(t *testing.T) {
	t.Run("DNS failure returns DNSError", func(t *testing.T) {
		_, err := parseTarget("nonexistent.invalid.host.example", 80, false)
		require.Error(t, err)
		var dnsErr *DNSError
		assert.True(t, errors.As(err, &dnsErr), "expected DNSError, got %T: %v", err, err)
	})

	t.Run("invalid port returns InvalidTargetError", func(t *testing.T) {
		_, err := parseTarget("127.0.0.1:99999", 80, false)
		require.Error(t, err)
		var targetErr *InvalidTargetError
		assert.True(t, errors.As(err, &targetErr), "expected InvalidTargetError, got %T: %v", err, err)
	})

	t.Run("unknown protocol returns InvalidTargetError", func(t *testing.T) {
		params := TracerouteParams{Hostname: "127.0.0.1", Protocol: "ftp"}
		_, err := runTracerouteOnce(context.Background(), params, 80)
		require.Error(t, err)
		var targetErr *InvalidTargetError
		assert.True(t, errors.As(err, &targetErr), "expected InvalidTargetError, got %T: %v", err, err)
	})
}
