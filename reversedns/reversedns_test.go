package reversedns

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/DataDog/datadog-traceroute/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetReverseDns(t *testing.T) {
	tests := []struct {
		name              string
		ipAddress         string
		fakeRDns          []string
		fakeErr           error
		expectedRDnsNames []string
		expectedErr       string
	}{
		{
			name:              "one valid rDNS name in response",
			ipAddress:         "1.1.1.1",
			fakeRDns:          []string{"foo.com"},
			fakeErr:           nil,
			expectedRDnsNames: []string{"foo.com"},
			expectedErr:       "",
		},
		{
			name:              "multiple valid rDNS name in response",
			ipAddress:         "1.1.1.1",
			fakeRDns:          []string{"foo.com", "bar.com"},
			fakeErr:           nil,
			expectedRDnsNames: []string{"foo.com", "bar.com"},
			expectedErr:       "",
		},
		{
			name:              "error case",
			ipAddress:         "1.1.1.1",
			fakeRDns:          nil,
			fakeErr:           errors.New("some error"),
			expectedRDnsNames: nil,
			expectedErr:       "failed to get reverse dns: some error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache.Cache.Flush()

			LookupAddrFn = func(_ context.Context, _ string) ([]string, error) {
				return tt.fakeRDns, tt.fakeErr
			}
			defer func() { LookupAddrFn = net.DefaultResolver.LookupAddr }()

			actualRdns, err := GetReverseDnsContext(context.Background(), tt.ipAddress)
			if tt.expectedErr != "" {
				require.EqualError(t, err, tt.expectedErr)
			}
			assert.Equal(t, tt.expectedRDnsNames, actualRdns)
		})
	}
}

func TestGetReverseDnsForIP(t *testing.T) {
	tests := []struct {
		name              string
		ipAddress         net.IP
		fakeRDns          []string
		fakeErr           error
		expectedRDnsNames []string
		expectedErr       string
	}{
		{
			name:              "one valid rDNS name in response",
			ipAddress:         net.ParseIP("1.1.1.1"),
			fakeRDns:          []string{"foo.com"},
			fakeErr:           nil,
			expectedRDnsNames: []string{"foo.com"},
			expectedErr:       "",
		},
		{
			name:              "invalid nil IP",
			ipAddress:         nil,
			fakeRDns:          nil,
			fakeErr:           nil,
			expectedRDnsNames: nil,
			expectedErr:       "invalid nil IP address",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache.Cache.Flush()

			LookupAddrFn = func(_ context.Context, _ string) ([]string, error) {
				return tt.fakeRDns, tt.fakeErr
			}
			defer func() { LookupAddrFn = net.DefaultResolver.LookupAddr }()

			actualRdns, err := GetReverseDnsForIPContext(context.Background(), tt.ipAddress)
			if tt.expectedErr != "" {
				require.EqualError(t, err, tt.expectedErr)
			}
			assert.Equal(t, tt.expectedRDnsNames, actualRdns)
		})
	}
}

func TestGetReverseDns_RespectsCallerContext(t *testing.T) {
	cache.Cache.Flush()

	LookupAddrFn = func(ctx context.Context, _ string) ([]string, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	defer func() { LookupAddrFn = net.DefaultResolver.LookupAddr }()

	// The caller's context has a much shorter deadline than reverseDnsDefaultTimeout,
	// so it should be what actually bounds the lookup.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := GetReverseDnsContext(ctx, "1.2.3.4")
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, elapsed, reverseDnsDefaultTimeout, "should be bounded by the caller's shorter deadline, not the internal default")
}

func TestGetReverseDnsForIPs_PropagatesContext(t *testing.T) {
	cache.Cache.Flush()

	LookupAddrFn = func(ctx context.Context, _ string) ([]string, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	defer func() { LookupAddrFn = net.DefaultResolver.LookupAddr }()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	start := time.Now()
	result, err := GetReverseDnsForIPsContext(ctx, []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("1.2.3.5")})
	elapsed := time.Since(start)

	require.NoError(t, err) // per-IP failures are swallowed, not returned
	assert.Empty(t, result)
	assert.Less(t, elapsed, reverseDnsDefaultTimeout, "should be bounded by the caller's shorter deadline, not the internal default")
}
