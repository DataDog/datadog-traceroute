package reversedns

import (
	"context"
	"errors"
	"net"
	"testing"

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
			LookupAddrFn = func(_ context.Context, _ string) ([]string, error) {
				return tt.fakeRDns, tt.fakeErr
			}
			defer func() { LookupAddrFn = net.DefaultResolver.LookupAddr }()

			actualRdns, err := GetReverseDns(tt.ipAddress)
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
			LookupAddrFn = func(_ context.Context, _ string) ([]string, error) {
				return tt.fakeRDns, tt.fakeErr
			}
			defer func() { LookupAddrFn = net.DefaultResolver.LookupAddr }()

			actualRdns, err := GetReverseDnsForIP(tt.ipAddress)
			if tt.expectedErr != "" {
				require.EqualError(t, err, tt.expectedErr)
			}
			assert.Equal(t, tt.expectedRDnsNames, actualRdns)
		})
	}
}
