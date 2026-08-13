package traceroute

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/log"
	"github.com/DataDog/datadog-traceroute/publicip"
	"github.com/DataDog/datadog-traceroute/result"
	"github.com/DataDog/datadog-traceroute/reversedns"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type controlledDeadlineContext struct {
	context.Context
	deadline time.Time
	done     chan struct{}
	expired  atomic.Bool
	once     sync.Once
}

// newControlledDeadlineContext lets tests deterministically expire a caller deadline.
func newControlledDeadlineContext() *controlledDeadlineContext {
	return &controlledDeadlineContext{
		Context:  context.Background(),
		deadline: time.Now().Add(time.Hour),
		done:     make(chan struct{}),
	}
}

func (c *controlledDeadlineContext) Deadline() (time.Time, bool) {
	return c.deadline, true
}

func (c *controlledDeadlineContext) Done() <-chan struct{} {
	return c.done
}

func (c *controlledDeadlineContext) Err() error {
	if c.expired.Load() {
		return context.DeadlineExceeded
	}
	return nil
}

func (c *controlledDeadlineContext) expire() {
	c.once.Do(func() {
		c.expired.Store(true)
		close(c.done)
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

func Test_e2eQueriesDelay(t *testing.T) {
	tests := []struct {
		name     string
		params   TracerouteParams
		expected time.Duration
	}{
		{
			name: "total timeout set: reserves overhead and the final probe timeout",
			params: TracerouteParams{
				TotalTimeout: 500 * time.Millisecond,
				Timeout:      100 * time.Millisecond,
				E2eQueries:   5,
			},
			expected: 87500 * time.Microsecond,
		},
		{
			name: "total timeout set: capped at 1 second",
			params: TracerouteParams{
				TotalTimeout: 100 * time.Second,
				Timeout:      time.Second,
				E2eQueries:   2,
			},
			expected: 1 * time.Second,
		},
		{
			name: "no total timeout: falls back to legacy MaxTTL*Timeout/E2eQueries formula",
			params: TracerouteParams{
				MaxTTL:     30,
				Timeout:    100 * time.Millisecond,
				E2eQueries: 3,
			},
			expected: (30 * 100 * time.Millisecond) / 3,
		},
		{
			name: "no total timeout: legacy formula capped at 1 second",
			params: TracerouteParams{
				MaxTTL:     30,
				Timeout:    time.Second,
				E2eQueries: 2,
			},
			expected: 1 * time.Second,
		},
		{
			name: "no timeout set: legacy pacing uses the effective default timeout",
			params: TracerouteParams{
				MaxTTL:     30,
				E2eQueries: 100,
			},
			expected: 900 * time.Millisecond,
		},
		{
			name: "probe timeout consumes the complete pacing budget",
			params: TracerouteParams{
				TotalTimeout: 200 * time.Millisecond,
				MaxTTL:       30,
				Timeout:      time.Hour, // would dominate the legacy formula if it were used
				E2eQueries:   2,
			},
			expected: 0,
		},
		{
			name: "one e2e query requires no pacing delay",
			params: TracerouteParams{
				TotalTimeout: 10 * time.Second,
				Timeout:      300 * time.Millisecond,
				E2eQueries:   1,
			},
			expected: 0,
		},
		{
			name: "default values reserve the derived final probe timeout",
			params: TracerouteParams{
				TotalTimeout: 10 * time.Second,
				MaxTTL:       30,
				E2eQueries:   50,
			},
			expected: (9*time.Second - 300*time.Millisecond) / 49,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, e2eQueriesDelay(tt.params))
		})
	}
}

func TestRunTraceroute_ContextDeadline(t *testing.T) {
	defer func() { runTracerouteOnceFn = runTracerouteOnce }()

	tests := []struct {
		name         string
		totalTimeout time.Duration
		wantDeadline bool
		wantTimeout  time.Duration
	}{
		{
			name:         "zero total timeout leaves the context unbounded",
			totalTimeout: 0,
			wantDeadline: false,
			wantTimeout:  0,
		},
		{
			name:         "positive total timeout bounds the context passed to each probe",
			totalTimeout: 2 * time.Second,
			wantDeadline: true,
			wantTimeout:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var hadDeadline bool
			var probeTimeout time.Duration
			runTracerouteOnceFn = func(ctx context.Context, params TracerouteParams, _ int) (*result.TracerouteRun, error) {
				_, hadDeadline = ctx.Deadline()
				probeTimeout = params.Timeout
				return &result.TracerouteRun{}, nil
			}

			tr := NewTraceroute()
			params := TracerouteParams{
				Hostname:          "example.com",
				TracerouteQueries: 1,
				MaxTTL:            common.DefaultMaxTTL,
				TotalTimeout:      tt.totalTimeout,
			}
			_, err := tr.RunTraceroute(context.Background(), params)
			require.NoError(t, err)
			assert.Equal(t, tt.wantDeadline, hadDeadline)
			assert.Equal(t, tt.wantTimeout, probeTimeout)
		})
	}
}

func TestRunTraceroute_NegativeTotalTimeoutIsRejected(t *testing.T) {
	// direct library callers (e.g. datadog-agent) bypass CLI/HTTP query validation, so
	// RunTraceroute itself must reject a negative TotalTimeout rather than silently treating
	// it like a disabled deadline the way zero is documented to behave.
	defer func() { runTracerouteOnceFn = runTracerouteOnce }()

	called := false
	runTracerouteOnceFn = func(ctx context.Context, _ TracerouteParams, _ int) (*result.TracerouteRun, error) {
		called = true
		return &result.TracerouteRun{}, nil
	}

	tr := NewTraceroute()
	params := TracerouteParams{
		Hostname:          "example.com",
		TracerouteQueries: 1,
		MaxTTL:            common.DefaultMaxTTL,
		TotalTimeout:      -1 * time.Second,
	}
	_, err := tr.RunTraceroute(context.Background(), params)

	require.Error(t, err)
	var targetErr *InvalidTargetError
	assert.True(t, errors.As(err, &targetErr), "expected InvalidTargetError, got %T: %v", err, err)
	assert.False(t, called, "should reject before running any probes")
}

func TestRunTraceroute_ShortTotalTimeoutIsNotPreemptivelyRejected(t *testing.T) {
	// A TotalTimeout too small for MaxTTL * MinProbeTimeout under a naive serial
	// budget must NOT be rejected upfront: real drivers probe TTLs in parallel
	// (see common.TracerouteParallelParams.MaxTimeout), an E2E-only request
	// (TracerouteQueries=0) never even sends traceroute probes, and an explicit
	// Timeout below MinProbeTimeout is honored as-is. A serial-assuming feasibility
	// check would reject all of these even though they can complete within budget;
	// letting the run's own deadline handling decide is correct here instead.
	defer func() { runTracerouteOnceFn = runTracerouteOnce }()
	runTracerouteOnceFn = func(ctx context.Context, _ TracerouteParams, _ int) (*result.TracerouteRun, error) {
		return &result.TracerouteRun{}, nil
	}

	tr := NewTraceroute()
	_, err := tr.RunTraceroute(context.Background(), TracerouteParams{
		Hostname:          "example.com",
		TracerouteQueries: 1,
		MaxTTL:            common.DefaultMaxTTL,
		TotalTimeout:      time.Second,
	})

	require.NoError(t, err)
}

func TestRunTraceroute_NegativeProbeTimeoutIsRejected(t *testing.T) {
	tr := NewTraceroute()
	_, err := tr.RunTraceroute(context.Background(), TracerouteParams{
		Hostname: "example.com",
		MaxTTL:   common.DefaultMaxTTL,
		Timeout:  -time.Millisecond,
	})

	require.Error(t, err)
	var targetErr *InvalidTargetError
	assert.True(t, errors.As(err, &targetErr), "expected InvalidTargetError, got %T: %v", err, err)
}

func TestRunTraceroute_NegativeDelayIsRejected(t *testing.T) {
	tr := NewTraceroute()
	_, err := tr.RunTraceroute(context.Background(), TracerouteParams{
		Hostname: "example.com",
		MaxTTL:   common.DefaultMaxTTL,
		Delay:    -1,
	})

	require.Error(t, err)
	var targetErr *InvalidTargetError
	assert.True(t, errors.As(err, &targetErr), "expected InvalidTargetError, got %T: %v", err, err)
}

func TestLogTerminalOutcome(t *testing.T) {
	var debugMessages, warnMessages, errorMessages []string
	log.SetLogger(log.Logger{
		Debugf: func(format string, args ...interface{}) {
			debugMessages = append(debugMessages, fmt.Sprintf(format, args...))
		},
		Warnf: func(format string, args ...interface{}) error {
			warnMessages = append(warnMessages, fmt.Sprintf(format, args...))
			return nil
		},
		Errorf: func(format string, args ...interface{}) error {
			errorMessages = append(errorMessages, fmt.Sprintf(format, args...))
			return nil
		},
	})
	defer log.SetLogger(log.Logger{})

	params := TracerouteParams{
		Hostname:          "example.com",
		Protocol:          "udp",
		TracerouteQueries: 3,
	}

	logTerminalOutcome(params, 443, &result.Results{
		TestRunID: "test-id",
		Traceroute: result.Traceroute{
			Runs: []result.TracerouteRun{{}, {}},
		},
	}, nil)
	logTerminalOutcome(params, 443, nil, context.DeadlineExceeded)
	logTerminalOutcome(params, 443, nil, &net.DNSError{
		Err:       "network timeout",
		IsTimeout: true,
	})
	logTerminalOutcome(params, 443, nil, context.Canceled)

	require.Len(t, debugMessages, 1)
	assert.Contains(t, debugMessages[0], `traceroute_run_completed hostname="example.com" protocol="udp" outcome=success`)
	assert.Contains(t, debugMessages[0], "completed_runs=2 requested_runs=3 deadline_exceeded=false destination_port=443")
	assert.Contains(t, debugMessages[0], `test_run_id="test-id"`)

	require.Len(t, warnMessages, 2)
	assert.Contains(t, warnMessages[0], "outcome=timeout")
	assert.Contains(t, warnMessages[0], "completed_runs=0 requested_runs=3 deadline_exceeded=true destination_port=443")
	assert.NotContains(t, warnMessages[0], "test_run_id=")
	assert.Contains(t, warnMessages[1], "outcome=timeout")
	assert.Contains(t, warnMessages[1], "deadline_exceeded=false")

	require.Len(t, errorMessages, 1)
	assert.Contains(t, errorMessages[0], "outcome=error")
	assert.Contains(t, errorMessages[0], "completed_runs=0 requested_runs=3 deadline_exceeded=false destination_port=443")
	assert.NotContains(t, errorMessages[0], "test_run_id=")
}

func TestRunTraceroute_MaxTTLIsValidatedBeforeDriverConversion(t *testing.T) {
	tr := NewTraceroute()

	for _, maxTTL := range []int{-1, 0, common.MaxAllowedTTL + 1, 512} {
		t.Run(fmt.Sprintf("rejects %d", maxTTL), func(t *testing.T) {
			_, err := tr.RunTraceroute(context.Background(), TracerouteParams{
				Hostname: "example.com",
				MaxTTL:   maxTTL,
			})

			require.Error(t, err)
			var targetErr *InvalidTargetError
			assert.True(t, errors.As(err, &targetErr), "expected InvalidTargetError, got %T: %v", err, err)
			assert.Contains(t, err.Error(), "max TTL")
		})
	}

	t.Run("accepts uint8 maximum", func(t *testing.T) {
		results, err := tr.RunTraceroute(context.Background(), TracerouteParams{
			Hostname: "example.com",
			MaxTTL:   common.MaxAllowedTTL,
		})

		require.NoError(t, err)
		require.NotNil(t, results)
	})
}

func TestRunTraceroute_QueryCountsAreValidatedBeforeAllocation(t *testing.T) {
	defer func() { runTracerouteOnceFn = runTracerouteOnce }()

	called := false
	runTracerouteOnceFn = func(context.Context, TracerouteParams, int) (*result.TracerouteRun, error) {
		called = true
		return &result.TracerouteRun{}, nil
	}

	tests := []struct {
		name   string
		params TracerouteParams
	}{
		{
			name: "negative traceroute queries",
			params: TracerouteParams{
				TracerouteQueries: -1,
			},
		},
		{
			name: "excessive traceroute queries",
			params: TracerouteParams{
				TracerouteQueries: common.MaxTracerouteQueries + 1,
			},
		},
		{
			name: "negative E2E queries",
			params: TracerouteParams{
				E2eQueries: -1,
			},
		},
		{
			name: "excessive E2E queries",
			params: TracerouteParams{
				E2eQueries: common.MaxE2eQueries + 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called = false
			tt.params.Hostname = "example.com"
			tt.params.MaxTTL = common.DefaultMaxTTL

			_, err := NewTraceroute().RunTraceroute(context.Background(), tt.params)

			require.Error(t, err)
			var targetErr *InvalidTargetError
			assert.True(t, errors.As(err, &targetErr), "expected InvalidTargetError, got %T: %v", err, err)
			assert.False(t, called, "query count must be rejected before starting or allocating probe runs")
		})
	}

	t.Run("maximum values are accepted", func(t *testing.T) {
		runTracerouteOnceFn = func(context.Context, TracerouteParams, int) (*result.TracerouteRun, error) {
			return &result.TracerouteRun{}, nil
		}

		results, err := NewTraceroute().RunTraceroute(context.Background(), TracerouteParams{
			Hostname:          "example.com",
			MaxTTL:            common.DefaultMaxTTL,
			Timeout:           time.Nanosecond,
			TracerouteQueries: common.MaxTracerouteQueries,
			E2eQueries:        common.MaxE2eQueries,
		})

		require.NoError(t, err)
		require.NotNil(t, results)
		assert.Len(t, results.Traceroute.Runs, common.MaxTracerouteQueries)
		assert.Len(t, results.E2eProbe.RTTs, common.MaxE2eQueries)
	})
}

func TestRunTraceroute_TotalTimeoutCancelsSlowProbes(t *testing.T) {
	defer func() { runTracerouteOnceFn = runTracerouteOnce }()

	runTracerouteOnceFn = func(ctx context.Context, _ TracerouteParams, _ int) (*result.TracerouteRun, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	tr := NewTraceroute()
	params := TracerouteParams{
		Hostname:          "example.com",
		TracerouteQueries: 3,
		// A small MaxTTL keeps the minimum-feasible-timeout check satisfied at 50ms.
		MaxTTL:       1,
		TotalTimeout: 50 * time.Millisecond,
		// Deliberately much larger than TotalTimeout to prove the overall run
		// deadline is what stops the probes, not the per-hop Timeout.
		Timeout: time.Hour,
	}

	start := time.Now()
	_, err := tr.RunTraceroute(context.Background(), params)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, elapsed, 1*time.Second, "should be canceled by TotalTimeout rather than waiting on the much larger per-hop Timeout")
}

func TestRunTraceroute_RequestErrorWinsDeadlineRace(t *testing.T) {
	defer func() { runTracerouteOnceFn = runTracerouteOnce }()

	ctx := newControlledDeadlineContext()
	runTracerouteOnceFn = func(_ context.Context, _ TracerouteParams, _ int) (*result.TracerouteRun, error) {
		ctx.expire()
		return nil, &InvalidTargetError{Err: fmt.Errorf("unknown protocol: %q", "ftp")}
	}

	results, err := NewTraceroute().RunTraceroute(ctx, TracerouteParams{
		Hostname:          "127.0.0.1",
		Protocol:          "ftp",
		TracerouteQueries: 1,
		MaxTTL:            common.DefaultMaxTTL,
	})

	require.Nil(t, results)
	var invalidTargetErr *InvalidTargetError
	require.ErrorAs(t, err, &invalidTargetErr)
	assert.Equal(t, ErrCodeInvalidRequest, ClassifyError(err).Code)
}

func TestRunTraceroute_CallerDeadlineDiscardsCompletedRuns(t *testing.T) {
	defer func() { runTracerouteOnceFn = runTracerouteOnce }()

	var calls atomic.Int32
	completed := make(chan struct{})
	runTracerouteOnceFn = func(ctx context.Context, _ TracerouteParams, _ int) (*result.TracerouteRun, error) {
		if calls.Add(1) == 1 {
			close(completed)
			return &result.TracerouteRun{
				Hops: []*result.TracerouteHop{
					{IPAddress: net.ParseIP("1.2.3.4"), RTT: 10, IsDest: true},
				},
			}, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}

	ctx := newControlledDeadlineContext()
	go func() {
		<-completed
		ctx.expire()
	}()
	results, err := NewTraceroute().RunTraceroute(ctx, TracerouteParams{
		Hostname:          "example.com",
		TracerouteQueries: 3,
		MaxTTL:            common.DefaultMaxTTL,
	})

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Nil(t, results)
}

func TestRunTraceroute_CallerDeadlineDiscardsCompletedE2eOnlyResults(t *testing.T) {
	defer func() { runTracerouteOnceFn = runTracerouteOnce }()

	ctx := newControlledDeadlineContext()
	runTracerouteOnceFn = func(_ context.Context, _ TracerouteParams, _ int) (*result.TracerouteRun, error) {
		ctx.expire()
		return &result.TracerouteRun{
			Hops: []*result.TracerouteHop{
				{IPAddress: net.ParseIP("1.2.3.4"), RTT: 10, IsDest: true},
			},
		}, nil
	}

	results, err := NewTraceroute().RunTraceroute(ctx, TracerouteParams{
		Hostname:          "example.com",
		TracerouteQueries: 0,
		E2eQueries:        1,
		MaxTTL:            common.DefaultMaxTTL,
	})

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Nil(t, results)
}

func TestRunTraceroute_DeadlineDiscardsIncompleteE2eProbeSet(t *testing.T) {
	defer func() { runTracerouteOnceFn = runTracerouteOnce }()

	tracerouteCompleted := make(chan struct{})
	firstE2eCompleted := make(chan struct{})
	secondE2eStarted := make(chan struct{})
	var e2eCalls atomic.Int32
	runTracerouteOnceFn = func(ctx context.Context, params TracerouteParams, _ int) (*result.TracerouteRun, error) {
		run := &result.TracerouteRun{
			Hops: []*result.TracerouteHop{
				{IPAddress: net.ParseIP("1.2.3.4"), RTT: 10, IsDest: true},
			},
		}
		if params.MinTTL != params.MaxTTL {
			close(tracerouteCompleted)
			return run, nil
		}
		if e2eCalls.Add(1) == 1 {
			close(firstE2eCompleted)
			return run, nil
		}
		close(secondE2eStarted)
		<-ctx.Done()
		return nil, ctx.Err()
	}

	ctx := newControlledDeadlineContext()
	go func() {
		<-tracerouteCompleted
		<-firstE2eCompleted
		<-secondE2eStarted
		ctx.expire()
	}()

	results, err := NewTraceroute().RunTraceroute(ctx, TracerouteParams{
		Hostname:          "example.com",
		MinTTL:            1,
		MaxTTL:            common.DefaultMaxTTL,
		TracerouteQueries: 1,
		E2eQueries:        2,
	})

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Nil(t, results)
}

func TestRunTraceroute_BothTimeoutsCoexistOnHappyPath(t *testing.T) {
	defer func() { runTracerouteOnceFn = runTracerouteOnce }()

	runTracerouteOnceFn = func(_ context.Context, params TracerouteParams, _ int) (*result.TracerouteRun, error) {
		return &result.TracerouteRun{
			Hops: []*result.TracerouteHop{
				{IPAddress: net.ParseIP("1.2.3.4"), RTT: 10, IsDest: true},
			},
		}, nil
	}

	tr := NewTraceroute()
	params := TracerouteParams{
		Hostname:          "example.com",
		TracerouteQueries: 2,
		E2eQueries:        2,
		MaxTTL:            5,
		Timeout:           50 * time.Millisecond,
		TotalTimeout:      5 * time.Second,
	}

	results, err := tr.RunTraceroute(context.Background(), params)

	require.NoError(t, err)
	require.NotNil(t, results)
	assert.Len(t, results.Traceroute.Runs, 2)
	assert.Len(t, results.E2eProbe.RTTs, 2)
}

func TestRunTraceroute_AgentShapedFinalE2eTimeoutKeepsCompletionMargin(t *testing.T) {
	defer func() { runTracerouteOnceFn = runTracerouteOnce }()

	// Model the Agent's production-shaped defaults: normal traceroute concurrency,
	// MaxTTL 30, and the default nonzero E2E count. Only the final E2E response is
	// silent. It must consume its full derived probe window inside the 90% probe
	// budget, leaving the final 10% for test-level completion work.
	var e2eCalls atomic.Int32
	runTracerouteOnceFn = func(ctx context.Context, params TracerouteParams, _ int) (*result.TracerouteRun, error) {
		if params.MinTTL == params.MaxTTL {
			if e2eCalls.Add(1) == int32(common.DefaultNumE2eProbes) {
				<-ctx.Done()
				return nil, ctx.Err()
			}
		}
		return &result.TracerouteRun{
			Hops: []*result.TracerouteHop{
				{IPAddress: net.ParseIP("198.51.100.2"), RTT: 10, IsDest: true},
			},
		}, nil
	}

	const totalTimeout = 2 * time.Second
	start := time.Now()
	results, err := NewTraceroute().RunTraceroute(context.Background(), TracerouteParams{
		Hostname:          "example.com",
		MinTTL:            common.DefaultMinTTL,
		MaxTTL:            common.DefaultMaxTTL,
		TracerouteQueries: common.DefaultTracerouteQueries,
		E2eQueries:        common.DefaultNumE2eProbes,
		TotalTimeout:      totalTimeout,
	})
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, results)
	assert.Len(t, results.Traceroute.Runs, common.DefaultTracerouteQueries)
	assert.Len(t, results.E2eProbe.RTTs, common.DefaultNumE2eProbes)
	assert.Equal(t, int32(common.DefaultNumE2eProbes), e2eCalls.Load())
	assert.Less(t, elapsed, totalTimeout,
		"the silent final E2E probe must finish before the shared TotalTimeout")
}

func TestRunTraceroute_DeadlineDuringReverseDNSEnrichmentDiscardsResults(t *testing.T) {
	defer func() { runTracerouteOnceFn = runTracerouteOnce }()
	originalLookupAddrFn := reversedns.LookupAddrFn
	defer func() { reversedns.LookupAddrFn = originalLookupAddrFn }()

	runTracerouteOnceFn = func(context.Context, TracerouteParams, int) (*result.TracerouteRun, error) {
		return &result.TracerouteRun{
			Destination: result.TracerouteDestination{
				IPAddress: net.ParseIP("198.51.100.101"),
			},
			Hops: []*result.TracerouteHop{
				{IPAddress: net.ParseIP("198.51.100.102"), RTT: 10, IsDest: true},
			},
		}, nil
	}

	lookupStarted := make(chan struct{})
	var startedOnce sync.Once
	reversedns.LookupAddrFn = func(ctx context.Context, _ string) ([]string, error) {
		startedOnce.Do(func() { close(lookupStarted) })
		<-ctx.Done()
		return nil, ctx.Err()
	}

	results, err := NewTraceroute().RunTraceroute(context.Background(), TracerouteParams{
		Hostname:          "example.com",
		MaxTTL:            1,
		TracerouteQueries: 1,
		E2eQueries:        1,
		ReverseDns:        true,
		TotalTimeout:      50 * time.Millisecond,
	})

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Nil(t, results)
	select {
	case <-lookupStarted:
	default:
		t.Fatal("reverse-DNS enrichment was not exercised")
	}
}

func TestRunTraceroute_CancellationDuringReverseDNSEnrichmentDiscardsResults(t *testing.T) {
	defer func() { runTracerouteOnceFn = runTracerouteOnce }()
	originalLookupAddrFn := reversedns.LookupAddrFn
	defer func() { reversedns.LookupAddrFn = originalLookupAddrFn }()

	runTracerouteOnceFn = func(context.Context, TracerouteParams, int) (*result.TracerouteRun, error) {
		return &result.TracerouteRun{
			Destination: result.TracerouteDestination{
				IPAddress: net.ParseIP("198.51.100.103"),
			},
			Hops: []*result.TracerouteHop{
				{IPAddress: net.ParseIP("198.51.100.104"), RTT: 10, IsDest: true},
			},
		}, nil
	}

	lookupStarted := make(chan struct{})
	var startedOnce sync.Once
	reversedns.LookupAddrFn = func(ctx context.Context, _ string) ([]string, error) {
		startedOnce.Do(func() { close(lookupStarted) })
		<-ctx.Done()
		return nil, ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-lookupStarted
		cancel()
	}()

	results, err := NewTraceroute().RunTraceroute(ctx, TracerouteParams{
		Hostname:          "example.com",
		MaxTTL:            common.DefaultMaxTTL,
		TracerouteQueries: 1,
		E2eQueries:        1,
		ReverseDns:        true,
	})

	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, results)
}

func TestRunTraceroute_E2ePacingStopsOnCancellation(t *testing.T) {
	defer func() { runTracerouteOnceFn = runTracerouteOnce }()

	started := make(chan struct{})
	var startedOnce sync.Once
	runTracerouteOnceFn = func(ctx context.Context, _ TracerouteParams, _ int) (*result.TracerouteRun, error) {
		startedOnce.Do(func() { close(started) })
		<-ctx.Done()
		return nil, ctx.Err()
	}

	tr := NewTraceroute()
	params := TracerouteParams{
		Hostname:   "example.com",
		E2eQueries: 5,
		MaxTTL:     common.MaxAllowedTTL,
		Timeout:    time.Second, // legacy e2eQueriesDelay formula yields the 1s cap between probes
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-started
		cancel()
	}()

	start := time.Now()
	results, err := tr.RunTraceroute(ctx, params)
	elapsed := time.Since(start)

	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, results)
	assert.Less(t, elapsed, 1*time.Second, "pacing loop should stop scheduling new probes once ctx is canceled, not sleep through all remaining delays")
}

func TestRunTraceroute_PublicIPCollectionStartsConcurrentlyWithE2ePacing(t *testing.T) {
	defer func() { runTracerouteOnceFn = runTracerouteOnce }()

	runTracerouteOnceFn = func(_ context.Context, _ TracerouteParams, _ int) (*result.TracerouteRun, error) {
		return &result.TracerouteRun{
			Hops: []*result.TracerouteHop{
				{IPAddress: net.ParseIP("1.2.3.4"), RTT: 10, IsDest: true},
			},
		}, nil
	}

	start := time.Now()
	var getIPCalledAt time.Duration

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockFetcher := publicip.NewMockFetcher(ctrl)
	mockFetcher.EXPECT().GetIP(gomock.Any()).DoAndReturn(func(_ context.Context) (net.IP, error) {
		getIPCalledAt = time.Since(start)
		return net.ParseIP("8.8.8.8"), nil
	})

	tr := NewTraceroute()
	tr.publicIPFetcher = mockFetcher

	params := TracerouteParams{
		E2eQueries:            3,
		MaxTTL:                1_000_000,
		Timeout:               time.Second, // legacy formula yields the 1s cap between e2e probes
		CollectSourcePublicIP: true,
	}

	_, err := tr.runTracerouteMulti(context.Background(), params, 42)

	require.NoError(t, err)
	assert.Less(t, getIPCalledAt, 500*time.Millisecond, "public IP collection should start concurrently with e2e pacing, not only after it finishes")
}
