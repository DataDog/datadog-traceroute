package traceroute

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/result"
	"github.com/DataDog/datadog-traceroute/sack"
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
		results, err := performTCPFallback(TCPConfigSYN, doSyn, doSack, doSynSocket)
		require.NoError(t, err)
		require.Equal(t, dummySyn, results)

		doSyn = func() (*result.TracerouteRun, error) {
			return nil, dummyErr
		}
		// error case
		results, err = performTCPFallback(TCPConfigSYN, doSyn, doSack, doSynSocket)
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
		results, err := performTCPFallback(TCPConfigSACK, doSyn, doSack, doSynSocket)
		require.NoError(t, err)
		require.Equal(t, dummySack, results)

		doSack = func() (*result.TracerouteRun, error) {
			return nil, dummyErr
		}
		// error case
		results, err = performTCPFallback(TCPConfigSACK, doSyn, doSack, doSynSocket)
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
		results, err := performTCPFallback(TCPConfigPreferSACK, doSyn, doSack, doSynSocket)
		require.NoError(t, err)
		require.Equal(t, dummySack, results)

		doSack = func() (*result.TracerouteRun, error) {
			return nil, dummyErr
		}
		// error case (sack encounters a fatal error and does not fall back to SYN)
		results, err = performTCPFallback(TCPConfigPreferSACK, doSyn, doSack, doSynSocket)
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
		results, err := performTCPFallback(TCPConfigPreferSACK, doSyn, doSack, doSynSocket)
		require.NoError(t, err)
		require.Equal(t, dummySyn, results)

		doSyn = func() (*result.TracerouteRun, error) {
			return nil, dummyErr
		}
		// error case
		results, err = performTCPFallback(TCPConfigPreferSACK, doSyn, doSack, doSynSocket)
		require.Equal(t, dummyErr, err)
		require.Nil(t, results)
	})

	t.Run("prefer SACK preserves deadline classification", func(t *testing.T) {
		doSyn := neverCalled(t)
		doSack := func() (*result.TracerouteRun, error) {
			return nil, fmt.Errorf("SACK deadline: %w", context.DeadlineExceeded)
		}
		doSynSocket := neverCalled(t)

		results, err := performTCPFallback(TCPConfigPreferSACK, doSyn, doSack, doSynSocket)

		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Nil(t, results)
	})

	t.Run("force SYN socket", func(t *testing.T) {
		doSyn := neverCalled(t)
		doSack := neverCalled(t)
		doSynSocket := func() (*result.TracerouteRun, error) {
			return dummySynSocket, nil
		}
		// success case
		results, err := performTCPFallback(TCPConfigSYNSocket, doSyn, doSack, doSynSocket)
		require.NoError(t, err)
		require.Equal(t, dummySynSocket, results)

		doSynSocket = func() (*result.TracerouteRun, error) {
			return nil, dummyErr
		}
		// error case
		results, err = performTCPFallback(TCPConfigSYNSocket, doSyn, doSack, doSynSocket)
		require.Equal(t, dummyErr, err)
		require.Nil(t, results)
	})
}

func Test_effectiveProbeTimeout(t *testing.T) {
	tests := []struct {
		name     string
		params   TracerouteParams
		expected time.Duration
	}{
		{
			name:     "explicit Timeout is unchanged when TotalTimeout is shorter",
			params:   TracerouteParams{Timeout: 3 * time.Second, TotalTimeout: 500 * time.Millisecond, MaxTTL: 30},
			expected: 3 * time.Second,
		},
		{
			name:     "explicit Timeout is unchanged when TotalTimeout is longer",
			params:   TracerouteParams{Timeout: 10 * time.Millisecond, TotalTimeout: 10 * time.Second, MaxTTL: 30},
			expected: 10 * time.Millisecond,
		},
		{
			name:     "neither Timeout nor TotalTimeout set uses the legacy default",
			params:   TracerouteParams{MaxTTL: 30},
			expected: 3 * time.Second,
		},
		{
			name:     "TotalTimeout derives a per-probe timeout",
			params:   TracerouteParams{TotalTimeout: 10 * time.Second, MaxTTL: 30},
			expected: 300 * time.Millisecond,
		},
		{
			name:     "small TotalTimeout uses the exact duration formula",
			params:   TracerouteParams{TotalTimeout: time.Nanosecond, MaxTTL: 30},
			expected: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, effectiveProbeTimeout(tt.params))
		})
	}
}

func TestRunE2eProbeOnceBoundsEntireQueryWithProbeTimeout(t *testing.T) {
	originalRunTracerouteOnceFn := runTracerouteOnceFn
	defer func() { runTracerouteOnceFn = originalRunTracerouteOnceFn }()

	const probeTimeout = 2 * time.Second
	var probeCtx context.Context
	var deadline time.Time
	runTracerouteOnceFn = func(ctx context.Context, _ TracerouteParams, _ int) (*result.TracerouteRun, error) {
		probeCtx = ctx
		var ok bool
		deadline, ok = ctx.Deadline()
		require.True(t, ok)
		return &result.TracerouteRun{}, nil
	}

	startedAt := time.Now()
	_, err := runE2eProbeOnce(context.Background(), TracerouteParams{
		MaxTTL:  common.DefaultMaxTTL,
		Timeout: probeTimeout,
	}, common.DefaultPort)

	require.NoError(t, err)
	assert.WithinDuration(t, startedAt.Add(probeTimeout), deadline, 100*time.Millisecond)
	require.NotNil(t, probeCtx)
	assert.ErrorIs(t, probeCtx.Err(), context.Canceled)
}

type serialProgressDriver struct {
	currentTTL atomic.Uint32
}

func (d *serialProgressDriver) GetDriverInfo() common.TracerouteDriverInfo {
	return common.TracerouteDriverInfo{SupportsParallel: false}
}

func (d *serialProgressDriver) SendProbe(ttl uint8) error {
	d.currentTTL.Store(uint32(ttl))
	return nil
}

func (d *serialProgressDriver) ReceiveProbe(timeout time.Duration) (*common.ProbeResponse, error) {
	if d.currentTTL.Load() == 1 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		<-timer.C
		return nil, &common.ReceiveProbeNoPktError{Err: errors.New("no packet")}
	}
	return &common.ProbeResponse{TTL: 2, IsDest: true}, nil
}

func TestTotalTimeoutOnlyDerivesProbeTimeoutForSerialProgress(t *testing.T) {
	params := TracerouteParams{
		TotalTimeout: 200 * time.Millisecond,
		MinTTL:       1,
		MaxTTL:       2,
	}
	probeTimeout := effectiveProbeTimeout(params)
	require.Equal(t, 90*time.Millisecond, probeTimeout)

	ctx, cancel := context.WithTimeout(context.Background(), params.TotalTimeout)
	defer cancel()
	results, err := common.TracerouteSerial(ctx, &serialProgressDriver{}, common.TracerouteSerialParams{
		TracerouteParams: common.TracerouteParams{
			MinTTL:            uint8(params.MinTTL),
			MaxTTL:            uint8(params.MaxTTL),
			TracerouteTimeout: probeTimeout,
			PollFrequency:     5 * time.Millisecond,
		},
	})

	require.NoError(t, err)
	require.Len(t, results, 2)
	require.NotNil(t, results[1], "TTL 2 must be probed after TTL 1 times out")
	assert.True(t, results[1].IsDest)
}

func TestExplicitProbeTimeoutAdvancesSerialRunBeforeTotalTimeout(t *testing.T) {
	// The staged Agent rollout sends both values. The shorter per-probe timeout must
	// advance past a silent hop without consuming the independent whole-run budget.
	params := TracerouteParams{
		TotalTimeout: 200 * time.Millisecond,
		Timeout:      40 * time.Millisecond,
		MinTTL:       1,
		MaxTTL:       2,
	}
	probeTimeout := effectiveProbeTimeout(params)
	require.Equal(t, params.Timeout, probeTimeout)

	ctx, cancel := context.WithTimeout(context.Background(), params.TotalTimeout)
	defer cancel()
	start := time.Now()
	results, err := common.TracerouteSerial(ctx, &serialProgressDriver{}, common.TracerouteSerialParams{
		TracerouteParams: common.TracerouteParams{
			MinTTL:            uint8(params.MinTTL),
			MaxTTL:            uint8(params.MaxTTL),
			TracerouteTimeout: probeTimeout,
			PollFrequency:     5 * time.Millisecond,
		},
	})
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.Len(t, results, 2)
	require.NotNil(t, results[1], "TTL 2 must be probed after TTL 1 reaches its explicit timeout")
	assert.True(t, results[1].IsDest)
	assert.GreaterOrEqual(t, elapsed, params.Timeout)
	assert.Less(t, elapsed, params.TotalTimeout,
		"the per-probe timeout should advance the serial run before TotalTimeout")
}

type noResponseParallelDriver struct{}

func (noResponseParallelDriver) GetDriverInfo() common.TracerouteDriverInfo {
	return common.TracerouteDriverInfo{SupportsParallel: true}
}

func (noResponseParallelDriver) SendProbe(uint8) error {
	return nil
}

func (noResponseParallelDriver) ReceiveProbe(timeout time.Duration) (*common.ProbeResponse, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	<-timer.C
	return nil, &common.ReceiveProbeNoPktError{Err: errors.New("no packet")}
}

func TestTotalTimeoutContextBoundsParallelRunnerIndependentlyFromProbeTimeout(t *testing.T) {
	// This is the other half of the staged dual-timeout contract: an explicit probe
	// timeout remains intact, while the shared TotalTimeout can still end the run first.
	params := TracerouteParams{
		TotalTimeout: 300 * time.Millisecond,
		Timeout:      2 * time.Second,
		MinTTL:       1,
		MaxTTL:       3,
		Delay:        10,
	}
	sendDelay := time.Duration(params.Delay) * time.Millisecond
	parallelParams := common.TracerouteParallelParams{
		TracerouteParams: common.TracerouteParams{
			MinTTL:            uint8(params.MinTTL),
			MaxTTL:            uint8(params.MaxTTL),
			TracerouteTimeout: effectiveProbeTimeout(params),
			PollFrequency:     5 * time.Millisecond,
			SendDelay:         sendDelay,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), params.TotalTimeout)
	defer cancel()
	start := time.Now()
	results, err := common.TracerouteParallel(ctx, noResponseParallelDriver{}, parallelParams)
	elapsed := time.Since(start)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Nil(t, results)
	assert.GreaterOrEqual(t, elapsed, params.TotalTimeout-50*time.Millisecond)
	assert.Less(t, elapsed, time.Second,
		"the shared TotalTimeout must stop the runner before the longer probe Timeout")
}
