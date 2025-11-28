package traceroute

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync/atomic"
	"testing"

	"github.com/DataDog/datadog-traceroute/result"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	runTracerouteOnceFnNoDestHop := func(ctx context.Context, params TracerouteParams, destinationPort int) (*result.TracerouteRun, error) {
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
				{IPAddress: net.ParseIP("1.2.3.6"), RTT: 30, IsDest: false},
			},
		}, nil
	}
	runTracerouteOnceFnSYN := func(ctx context.Context, params TracerouteParams, destinationPort int) (*result.TracerouteRun, error) {
		assert.Equal(t, "tcp", params.Protocol)
		assert.Equal(t, TCPConfigSYN, params.TCPMethod)
		return &result.TracerouteRun{}, nil
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
		{
			name:             "5 e2eprobe queries",
			params:           TracerouteParams{E2eQueries: 5},
			tracerouteOnceFn: runTracerouteOnceFnValid,
			expectedResults: &result.Results{
				Traceroute: result.Traceroute{},
				E2eProbe: result.E2eProbe{
					RTTs: []float64{30, 30, 30, 30, 30},
				},
			},
		},
		{
			name:             "e2eprobe doesnt reach destination",
			params:           TracerouteParams{E2eQueries: 5},
			tracerouteOnceFn: runTracerouteOnceFnNoDestHop,
			expectedResults: &result.Results{
				Traceroute: result.Traceroute{},
				E2eProbe: result.E2eProbe{
					RTTs: []float64{0, 0, 0, 0, 0},
				},
			},
		},
		{
			name: "e2eprobe with sack method uses syn",
			params: TracerouteParams{
				E2eQueries: 1,
				Protocol:   "tcp",
				TCPMethod:  "sack",
			},
			tracerouteOnceFn: runTracerouteOnceFnSYN,
			expectedResults: &result.Results{
				Traceroute: result.Traceroute{},
				E2eProbe: result.E2eProbe{
					RTTs: []float64{0},
				},
			},
		},
		{
			name: "e2eprobe with prefer_sack method uses syn",
			params: TracerouteParams{
				E2eQueries: 1,
				Protocol:   "tcp",
				TCPMethod:  "prefer_sack",
			},
			tracerouteOnceFn: runTracerouteOnceFnSYN,
			expectedResults: &result.Results{
				Traceroute: result.Traceroute{},
				E2eProbe: result.E2eProbe{
					RTTs: []float64{0},
				},
			},
		},
		{
			name: "e2eprobe with syn method uses syn",
			params: TracerouteParams{
				E2eQueries: 1,
				Protocol:   "tcp",
				TCPMethod:  "syn",
			},
			tracerouteOnceFn: runTracerouteOnceFnSYN,
			expectedResults: &result.Results{
				Traceroute: result.Traceroute{},
				E2eProbe: result.E2eProbe{
					RTTs: []float64{0},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			counter.Store(0)
			runTracerouteOnceFn = tt.tracerouteOnceFn
			defer func() { runTracerouteOnceFn = runTracerouteOnce }()

			traceroute := NewTraceroute()
			results, err := traceroute.runTracerouteMulti(context.Background(), tt.params, 42)
			for _, errMsg := range tt.expectedError {
				assert.ErrorContains(t, err, errMsg)
			}
			if results != nil {
				// Sort results by destination IP for deterministic comparison
				sort.Slice(results.Traceroute.Runs, func(i, j int) bool {
					return bytes.Compare(results.Traceroute.Runs[i].Destination.IPAddress,
						results.Traceroute.Runs[j].Destination.IPAddress) < 0
				})
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
