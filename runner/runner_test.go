package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"

	"github.com/DataDog/datadog-traceroute/result"
	"github.com/DataDog/datadog-traceroute/sack"
	"github.com/DataDog/datadog-traceroute/traceroute"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func neverCalled(t *testing.T) tracerouteImpl {
	return func() (*result.TracerouteRun, error) {
		t.Fatal("should not call this")
		return nil, fmt.Errorf("should not call this")
	}
}

func TestTCPFallback(t *testing.T) {
	dummySyn := &result.TracerouteRun{}
	dummySack := &result.TracerouteRun{}
	dummyErr := fmt.Errorf("test error")
	dummySackUnsupportedErr := &sack.NotSupportedError{
		Err: fmt.Errorf("dummy sack unsupported"),
	}
	dummySynSocket := &result.TracerouteRun{}

	t.Run("force SYN", func(t *testing.T) {
		doSyn := func() (*result.TracerouteRun, error) {
			return dummySyn, nil
		}
		doSack := neverCalled(t)
		doSynSocket := neverCalled(t)
		// success case
		results, err := performTCPFallback(traceroute.TCPConfigSYN, doSyn, doSack, doSynSocket)
		require.NoError(t, err)
		require.Equal(t, dummySyn, results)

		doSyn = func() (*result.TracerouteRun, error) {
			return nil, dummyErr
		}
		// error case
		results, err = performTCPFallback(traceroute.TCPConfigSYN, doSyn, doSack, doSynSocket)
		require.Equal(t, dummyErr, err)
		require.Nil(t, results)
	})

	t.Run("force SACK", func(t *testing.T) {
		doSyn := neverCalled(t)
		doSack := func() (*result.TracerouteRun, error) {
			return dummySack, nil
		}
		doSynSocket := neverCalled(t)
		// success case
		results, err := performTCPFallback(traceroute.TCPConfigSACK, doSyn, doSack, doSynSocket)
		require.NoError(t, err)
		require.Equal(t, dummySack, results)

		doSack = func() (*result.TracerouteRun, error) {
			return nil, dummyErr
		}
		// error case
		results, err = performTCPFallback(traceroute.TCPConfigSACK, doSyn, doSack, doSynSocket)
		require.Equal(t, dummyErr, err)
		require.Nil(t, results)
	})

	t.Run("prefer SACK - only running sack", func(t *testing.T) {
		doSyn := neverCalled(t)
		doSack := func() (*result.TracerouteRun, error) {
			return dummySack, nil
		}
		doSynSocket := neverCalled(t)
		// success case
		results, err := performTCPFallback(traceroute.TCPConfigPreferSACK, doSyn, doSack, doSynSocket)
		require.NoError(t, err)
		require.Equal(t, dummySack, results)

		doSack = func() (*result.TracerouteRun, error) {
			return nil, dummyErr
		}
		// error case (sack encounters a fatal error and does not fall back to SYN)
		results, err = performTCPFallback(traceroute.TCPConfigPreferSACK, doSyn, doSack, doSynSocket)
		require.ErrorIs(t, err, dummyErr)
		require.Nil(t, results)
	})

	t.Run("prefer SACK - fallback case", func(t *testing.T) {
		doSyn := func() (*result.TracerouteRun, error) {
			return dummySyn, nil
		}
		doSack := func() (*result.TracerouteRun, error) {
			// cause a fallback because the target doesn't support SACK
			return nil, dummySackUnsupportedErr
		}
		doSynSocket := neverCalled(t)
		// success case
		results, err := performTCPFallback(traceroute.TCPConfigPreferSACK, doSyn, doSack, doSynSocket)
		require.NoError(t, err)
		require.Equal(t, dummySyn, results)

		doSyn = func() (*result.TracerouteRun, error) {
			return nil, dummyErr
		}
		// error case
		results, err = performTCPFallback(traceroute.TCPConfigPreferSACK, doSyn, doSack, doSynSocket)
		require.Equal(t, dummyErr, err)
		require.Nil(t, results)
	})

	t.Run("force SYN socket", func(t *testing.T) {
		doSyn := neverCalled(t)
		doSack := neverCalled(t)
		doSynSocket := func() (*result.TracerouteRun, error) {
			return dummySynSocket, nil
		}
		// success case
		results, err := performTCPFallback(traceroute.TCPConfigSYNSocket, doSyn, doSack, doSynSocket)
		require.NoError(t, err)
		require.Equal(t, dummySynSocket, results)

		doSynSocket = func() (*result.TracerouteRun, error) {
			return nil, dummyErr
		}
		// error case
		results, err = performTCPFallback(traceroute.TCPConfigSYNSocket, doSyn, doSack, doSynSocket)
		require.Equal(t, dummyErr, err)
		require.Nil(t, results)
	})
}

func Test_runTracerouteMulti(t *testing.T) {
	var counter atomic.Int32

	runTracerouteOnceFnValid := func(ctx context.Context, params TracerouteParams, destinationPort int) (*result.TracerouteRun, error) {
		counter.Add(1)
		destIP := fmt.Sprintf("10.10.10.%d", counter.Load())
		return &result.TracerouteRun{
			Source: result.TracerouteSource{
				IPAddress: net.ParseIP("10.10.88.88"),
				Port:      1122,
			},
			Destination: result.TracerouteDestination{
				IPAddress: net.ParseIP(destIP),
			},
			Hops: []*result.TracerouteHop{
				{IPAddress: net.ParseIP("1.2.3.4"), RTT: 10},
				{IPAddress: net.ParseIP("1.2.3.5"), RTT: 30, IsDest: true},
			},
		}, nil
	}
	runTracerouteOnceFnError := func(ctx context.Context, params TracerouteParams, destinationPort int) (*result.TracerouteRun, error) {
		counter.Add(1)
		err := errors.New(fmt.Sprintf("error running traceroute %d", counter.Load()))
		return nil, err
	}
	defer func() { runTracerouteOnceFn = runTracerouteOnce }()
	tests := []struct {
		name             string
		params           TracerouteParams
		tracerouteOnceFn runTracerouteOnceFnType
		expectedResults  *result.Results
		expectedError    []string
	}{
		{
			name:             "1 traceroute query",
			params:           TracerouteParams{TracerouteQueries: 1},
			tracerouteOnceFn: runTracerouteOnceFnValid,
			expectedResults: &result.Results{
				Traceroute: result.Traceroute{
					Runs: []result.TracerouteRun{
						{
							Source: result.TracerouteSource{
								IPAddress: net.ParseIP("10.10.88.88"),
								Port:      1122,
							},
							Destination: result.TracerouteDestination{
								IPAddress: net.ParseIP("10.10.10.1"),
							},
							Hops: []*result.TracerouteHop{
								{IPAddress: net.ParseIP("1.2.3.4"), RTT: 10},
								{IPAddress: net.ParseIP("1.2.3.5"), RTT: 30, IsDest: true},
							},
						},
					},
				},
			},
		},
		{
			name:             "3 traceroute query",
			params:           TracerouteParams{TracerouteQueries: 3},
			tracerouteOnceFn: runTracerouteOnceFnValid,
			expectedResults: &result.Results{
				Traceroute: result.Traceroute{
					Runs: []result.TracerouteRun{
						{
							Source: result.TracerouteSource{
								IPAddress: net.ParseIP("10.10.88.88"),
								Port:      1122,
							},
							Destination: result.TracerouteDestination{
								IPAddress: net.ParseIP("10.10.10.1"),
							},
							Hops: []*result.TracerouteHop{
								{IPAddress: net.ParseIP("1.2.3.4"), RTT: 10},
								{IPAddress: net.ParseIP("1.2.3.5"), RTT: 30, IsDest: true},
							},
						},
						{
							Source: result.TracerouteSource{
								IPAddress: net.ParseIP("10.10.88.88"),
								Port:      1122,
							},
							Destination: result.TracerouteDestination{
								IPAddress: net.ParseIP("10.10.10.2"),
							},
							Hops: []*result.TracerouteHop{
								{IPAddress: net.ParseIP("1.2.3.4"), RTT: 10},
								{IPAddress: net.ParseIP("1.2.3.5"), RTT: 30, IsDest: true},
							},
						},
						{
							Source: result.TracerouteSource{
								IPAddress: net.ParseIP("10.10.88.88"),
								Port:      1122,
							},
							Destination: result.TracerouteDestination{
								IPAddress: net.ParseIP("10.10.10.3"),
							},
							Hops: []*result.TracerouteHop{
								{IPAddress: net.ParseIP("1.2.3.4"), RTT: 10},
								{IPAddress: net.ParseIP("1.2.3.5"), RTT: 30, IsDest: true},
							},
						},
					},
				},
			},
		},
		{
			name:             "errors",
			params:           TracerouteParams{TracerouteQueries: 2},
			tracerouteOnceFn: runTracerouteOnceFnError,
			expectedResults:  nil,
			expectedError: []string{
				"error running traceroute 1",
				"error running traceroute 2",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			counter.Store(0)
			runTracerouteOnceFn = tt.tracerouteOnceFn
			defer func() { runTracerouteOnceFn = runTracerouteOnce }()

			results, err := runTracerouteMulti(context.Background(), tt.params, 42)
			for _, errMsg := range tt.expectedError {
				assert.ErrorContains(t, err, errMsg)
			}
			expectedResultsJson, err := json.MarshalIndent(tt.expectedResults, "", "  ")
			require.NoError(t, err)
			actualResultsJson, err := json.MarshalIndent(results, "", "  ")
			require.NoError(t, err)
			assert.Equal(t, expectedResultsJson, actualResultsJson)
			assert.Equal(t, tt.expectedResults, results)
		})
	}
}
