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

	"github.com/DataDog/datadog-traceroute/log"
	"github.com/DataDog/datadog-traceroute/publicip"
	"github.com/DataDog/datadog-traceroute/result"
	"github.com/golang/mock/gomock"
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
		err := fmt.Errorf("error running traceroute %d", counter.Load())
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
		setupMockFetcher func(*gomock.Controller) publicip.Fetcher
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
		{
			name: "public IP enrichment",
			params: TracerouteParams{
				TracerouteQueries:     1,
				CollectSourcePublicIP: true,
			},
			tracerouteOnceFn: runTracerouteOnceFnValid,
			setupMockFetcher: func(ctrl *gomock.Controller) publicip.Fetcher {
				mockFetcher := publicip.NewMockFetcher(ctrl)
				mockFetcher.EXPECT().GetIP(gomock.Any()).Return(net.ParseIP("8.8.8.8"), nil)
				return mockFetcher
			},
			expectedResults: &result.Results{
				Source: result.Source{
					PublicIP: "8.8.8.8",
				},
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
			name: "public IP enrichment error",
			params: TracerouteParams{
				TracerouteQueries:     1,
				CollectSourcePublicIP: true,
			},
			tracerouteOnceFn: runTracerouteOnceFnValid,
			setupMockFetcher: func(ctrl *gomock.Controller) publicip.Fetcher {
				mockFetcher := publicip.NewMockFetcher(ctrl)
				mockFetcher.EXPECT().GetIP(gomock.Any()).Return(nil, errors.New("failed to fetch public IP"))
				return mockFetcher
			},
			expectedResults: &result.Results{
				Source: result.Source{
					PublicIP: "",
				},
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			counter.Store(0)
			runTracerouteOnceFn = tt.tracerouteOnceFn
			defer func() { runTracerouteOnceFn = runTracerouteOnce }()

			traceroute := NewTraceroute()
			if tt.setupMockFetcher != nil {
				ctrl := gomock.NewController(t)
				defer ctrl.Finish()
				mockFetcher := tt.setupMockFetcher(ctrl)
				traceroute.publicIPFetcher = mockFetcher
			}

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

func Test_runTracerouteMulti_partialFailure(t *testing.T) {
	var counter atomic.Int32
	// Alternate between success and failure
	runTracerouteOnceFnAlternating := func(ctx context.Context, params TracerouteParams, destinationPort int) (*result.TracerouteRun, error) {
		n := counter.Add(1)
		if n%2 == 0 {
			return nil, fmt.Errorf("simulated failure on run %d", n)
		}
		return &result.TracerouteRun{
			Source: result.TracerouteSource{
				IPAddress: net.ParseIP("10.10.88.88"),
				Port:      1122,
			},
			Destination: result.TracerouteDestination{
				IPAddress: net.ParseIP(fmt.Sprintf("10.10.10.%d", n)),
			},
			Hops: []*result.TracerouteHop{
				{IPAddress: net.ParseIP("1.2.3.4"), RTT: 10, IsDest: true},
			},
		}, nil
	}

	defer func() { runTracerouteOnceFn = runTracerouteOnce }()
	runTracerouteOnceFn = runTracerouteOnceFnAlternating

	// Capture warning logs
	var warnMessages []string
	origLogger := log.Logger{
		Warnf: func(format string, args ...interface{}) error {
			warnMessages = append(warnMessages, fmt.Sprintf(format, args...))
			return nil
		},
	}
	log.SetLogger(origLogger)
	defer log.SetLogger(log.Logger{})

	tr := NewTraceroute()
	results, err := tr.runTracerouteMulti(context.Background(), TracerouteParams{TracerouteQueries: 3}, 42)

	// Should succeed despite some failures
	require.NoError(t, err)
	require.NotNil(t, results)
	// At least 1 run should have succeeded (runs 1 and 3 succeed, run 2 fails)
	assert.GreaterOrEqual(t, len(results.Traceroute.Runs), 1)
	assert.LessOrEqual(t, len(results.Traceroute.Runs), 3)

	// Warning log should have been emitted with failure count
	require.Len(t, warnMessages, 1)
	assert.Contains(t, warnMessages[0], "Some traceroute runs failed")
	assert.Contains(t, warnMessages[0], "/3")
}

func Test_runTracerouteMulti_allFailSameError(t *testing.T) {
	// All runs fail with the same error — the returned error should be deduplicated
	runTracerouteOnceFnSameError := func(ctx context.Context, params TracerouteParams, destinationPort int) (*result.TracerouteRun, error) {
		return nil, fmt.Errorf("DNS resolution failed")
	}

	defer func() { runTracerouteOnceFn = runTracerouteOnce }()
	runTracerouteOnceFn = runTracerouteOnceFnSameError

	tr := NewTraceroute()
	_, err := tr.runTracerouteMulti(context.Background(), TracerouteParams{TracerouteQueries: 3}, 42)

	require.Error(t, err)
	// Should appear only once despite 3 runs failing with the same message
	assert.Equal(t, "DNS resolution failed", err.Error())
}

func Test_deduplicateErrors(t *testing.T) {
	tests := []struct {
		name     string
		input    []error
		expected int
	}{
		{
			name:     "empty",
			input:    []error{},
			expected: 0,
		},
		{
			name:     "all unique",
			input:    []error{fmt.Errorf("a"), fmt.Errorf("b"), fmt.Errorf("c")},
			expected: 3,
		},
		{
			name:     "all same",
			input:    []error{fmt.Errorf("same"), fmt.Errorf("same"), fmt.Errorf("same")},
			expected: 1,
		},
		{
			name:     "mixed",
			input:    []error{fmt.Errorf("a"), fmt.Errorf("b"), fmt.Errorf("a"), fmt.Errorf("c"), fmt.Errorf("b")},
			expected: 3,
		},
		{
			name:     "single",
			input:    []error{fmt.Errorf("only")},
			expected: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deduplicateErrors(tt.input)
			assert.Len(t, result, tt.expected)
		})
	}

	// Verify order preservation
	t.Run("preserves order", func(t *testing.T) {
		input := []error{fmt.Errorf("first"), fmt.Errorf("second"), fmt.Errorf("first"), fmt.Errorf("third")}
		result := deduplicateErrors(input)
		require.Len(t, result, 3)
		assert.Equal(t, "first", result[0].Error())
		assert.Equal(t, "second", result[1].Error())
		assert.Equal(t, "third", result[2].Error())
	})
}
