package traceroute

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/log"
	"github.com/DataDog/datadog-traceroute/publicip"
	"github.com/DataDog/datadog-traceroute/result"
)

type Traceroute struct {
	publicIPFetcher publicip.Fetcher
}

func NewTraceroute() *Traceroute {
	return &Traceroute{
		publicIPFetcher: publicip.NewPublicIPFetcher(),
	}
}

func (t Traceroute) RunTraceroute(ctx context.Context, params TracerouteParams) (results *result.Results, err error) {
	log.Infof("Running traceroute with params: %+v", params)

	runCtx := ctx
	destinationPort := params.Port
	if destinationPort == 0 {
		destinationPort = common.DefaultPort
	}
	defer func() {
		logTerminalOutcome(params, destinationPort, results, err)
	}()

	// Validate at the library boundary: callers that build TracerouteParams directly
	// (e.g. datadog-agent) bypass the CLI/HTTP validation, so a negative value here
	// must be rejected rather than silently disabling the deadline like zero does.
	if params.TotalTimeout < 0 {
		return nil, &InvalidTargetError{Err: fmt.Errorf("total timeout must not be negative, got %s", params.TotalTimeout)}
	}
	if params.TotalTimeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, params.TotalTimeout)
		defer cancel()
	}
	if params.Timeout < 0 {
		return nil, &InvalidTargetError{Err: fmt.Errorf("probe timeout must not be negative, got %s", params.Timeout)}
	}
	if params.Delay < 0 {
		return nil, &InvalidTargetError{Err: fmt.Errorf("delay must not be negative, got %d", params.Delay)}
	}
	if err := common.ValidateMaxTTL("max TTL", params.MaxTTL); err != nil {
		return nil, &InvalidTargetError{Err: err}
	}
	if err := common.ValidateQueryCount("traceroute queries", params.TracerouteQueries, common.MaxTracerouteQueries); err != nil {
		return nil, &InvalidTargetError{Err: err}
	}
	if err := common.ValidateQueryCount("E2E queries", params.E2eQueries, common.MaxE2eQueries); err != nil {
		return nil, &InvalidTargetError{Err: err}
	}

	var e2eComplete bool
	results, e2eComplete, err = t.runTracerouteMulti(runCtx, params, destinationPort)
	if err != nil {
		return nil, err
	}

	results.Protocol = params.Protocol
	results.Destination = result.Destination{
		Hostname: params.Hostname,
		Port:     destinationPort,
	}
	if params.ReverseDns {
		results.EnrichWithReverseDnsContext(runCtx)
	}

	// A deadline may expire during enrichment after traceroute queries have completed.
	// Keep only whole completed traceroute runs, and discard E2E measurements unless
	// the full requested E2E set already completed before the deadline.
	if keep, err := applyDeadlineOutcome(runCtx, params, results, e2eComplete); !keep {
		return nil, err
	}

	results.Normalize()
	if params.SkipPrivateHops {
		results.RemovePrivateHops()
	}

	// Normalization and filtering are part of RunTraceroute too. Re-check the context
	// after that synchronous work so a deadline or cancellation observed there follows
	// the same output contract as one observed during probing or enrichment.
	if keep, err := applyDeadlineOutcome(runCtx, params, results, e2eComplete); !keep {
		return nil, err
	}

	return results, nil
}

// applyDeadlineOutcome finalizes results against runCtx's terminal state. It returns
// keep=false when the caller must discard results entirely (explicit cancellation, or
// a deadline that fired before anything usable completed). Otherwise it marks results
// as partial (TimedOut, with E2eProbe cleared unless the full E2E set completed) and
// returns keep=true so the caller can continue using results.
//
// "Usable" means either a whole traceroute run completed, or no traceroute queries were
// requested at all (E2E-only) and the full E2E set completed — TracerouteQueries=0 makes
// results.Traceroute.Runs empty by construction, so that case can't be judged by run count.
func applyDeadlineOutcome(runCtx context.Context, params TracerouteParams, results *result.Results, e2eComplete bool) (keep bool, err error) {
	switch {
	case errors.Is(runCtx.Err(), context.Canceled):
		return false, context.Canceled
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		hasUsableResults := len(results.Traceroute.Runs) > 0 || (params.TracerouteQueries == 0 && e2eComplete)
		if !params.ReturnPartialResults || !hasUsableResults {
			return false, context.DeadlineExceeded
		}
		if !e2eComplete {
			results.E2eProbe = result.E2eProbe{}
		}
		results.TimedOut = true
	}
	return true, nil
}

func logTerminalOutcome(params TracerouteParams, destinationPort int, results *result.Results, runErr error) {
	completedRuns := 0
	testRunID := ""
	if results != nil {
		completedRuns = len(results.Traceroute.Runs)
		testRunID = results.TestRunID
	}

	deadlineExceeded := (results != nil && results.TimedOut) || errors.Is(runErr, context.DeadlineExceeded)
	timeoutOutcome := deadlineExceeded
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		timeoutOutcome = ClassifyError(runErr).Code == ErrCodeTimeout
	}
	outcome := "error"
	if timeoutOutcome {
		outcome = "timeout"
	} else if runErr == nil {
		outcome = "success"
	}

	message := fmt.Sprintf(
		"traceroute_run_completed hostname=%q protocol=%q outcome=%s completed_runs=%d requested_runs=%d deadline_exceeded=%t destination_port=%d",
		params.Hostname,
		params.Protocol,
		outcome,
		completedRuns,
		params.TracerouteQueries,
		deadlineExceeded,
		destinationPort,
	)
	if testRunID != "" {
		message += fmt.Sprintf(" test_run_id=%q", testRunID)
	}

	switch outcome {
	case "success":
		log.Debugf("%s", message)
	case "timeout":
		_ = log.Warnf("%s", message)
	default:
		_ = log.Errorf("%s", message)
	}
}

func (t Traceroute) runTracerouteMulti(ctx context.Context, params TracerouteParams, destinationPort int) (*result.Results, bool, error) {
	var wg sync.WaitGroup
	var results result.Results

	tracerouteQueryCount := params.TracerouteQueries
	tracerouteRuns := make([]*result.TracerouteRun, tracerouteQueryCount)
	tracerouteRunErrors := make([]error, tracerouteQueryCount)

	// regular traceroutes
	for i := 0; i < tracerouteQueryCount; i++ {
		wg.Add(1)
		go func(runIndex int) {
			defer wg.Done()
			trRun, err := runTracerouteOnceFn(ctx, params, destinationPort)
			if err == nil && trRun == nil {
				err = fmt.Errorf("traceroute run %d returned nil without an error", runIndex)
			}
			tracerouteRuns[runIndex] = trRun
			tracerouteRunErrors[runIndex] = err
		}(i)
	}

	// Launched up front (rather than after e2e pacing) so it runs concurrently with the
	// e2e probe loop below instead of only starting once that loop's pacing has elapsed.
	var sourcePublicIP string
	if params.CollectSourcePublicIP {
		log.Trace("collect public ip")
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip, err := t.publicIPFetcher.GetIP(ctx)
			if err != nil {
				log.Debugf("Error getting IP: %s", err)
				return
			}
			sourcePublicIP = ip.String()
		}()
	}

	e2eQueryCount := params.E2eQueries
	e2eRTTs := make([]float64, e2eQueryCount)
	launchedE2eQueries := 0
	var e2eInterruptedByCtx atomic.Bool
	if e2eQueryCount > 0 {
		delay := e2eQueriesDelay(params)
		log.Tracef("e2e query delay: %d msec", delay.Milliseconds())

		// e2e probes
		for i := 0; i < e2eQueryCount; i++ {
			// stop launching new probes once the caller/run context is done
			if ctx.Err() != nil {
				break
			}

			log.Tracef("send e2e probe #%d", i+1)
			wg.Add(1)
			launchedE2eQueries = i + 1
			go func(probeIndex int) {
				defer wg.Done()
				e2eRtt, err := runE2eProbeOnce(ctx, params, destinationPort)
				if err != nil {
					// runE2eProbeOnce bounds itself with its own per-probe child context, so
					// a DeadlineExceeded from that child on ordinary packet loss looks
					// identical to one from the run's own ctx. Only the latter means this
					// probe never got to complete its measurement; check the parent ctx
					// directly rather than inspecting the error to tell them apart.
					if ctx.Err() != nil {
						e2eInterruptedByCtx.Store(true)
					}
					log.Debugf("E2E probe error (recorded as 0 RTT): %s", err)
					return
				}
				e2eRTTs[probeIndex] = e2eRtt
			}(i)
			if i < (e2eQueryCount - 1) { // don't add delay for last query
				timer := time.NewTimer(delay)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
				}
			}
		}
	}

	wg.Wait()

	var tracerouteErrors []error
	for i, trRun := range tracerouteRuns {
		if err := tracerouteRunErrors[i]; err != nil {
			tracerouteErrors = append(tracerouteErrors, err)
			continue
		}
		if trRun != nil {
			results.Traceroute.Runs = append(results.Traceroute.Runs, *trRun)
		}
	}
	if launchedE2eQueries > 0 {
		results.E2eProbe.RTTs = e2eRTTs[:launchedE2eQueries]
	}
	results.Source.PublicIP = sourcePublicIP

	// The E2E set is complete only if every requested probe was launched and none of
	// them were cut short by the run context, as opposed to failing on their own merits.
	e2eComplete := launchedE2eQueries == e2eQueryCount && !e2eInterruptedByCtx.Load()

	var allTracerouteRunsFailedErr error
	if params.TracerouteQueries > 0 && len(results.Traceroute.Runs) == 0 && len(tracerouteErrors) > 0 {
		allTracerouteRunsFailedErr = errors.Join(deduplicateErrors(tracerouteErrors)...)
	}

	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		// Explicit cancellation is not a timeout and must never expose partial output.
		return nil, false, context.Canceled
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		// E2E results are meaningful only when the complete requested probe set finished.
		// A deadline can interrupt that set, so discard it unless it's complete.
		if !e2eComplete {
			results.E2eProbe = result.E2eProbe{}
		}
		hasUsableResults := len(results.Traceroute.Runs) > 0 || (params.TracerouteQueries == 0 && e2eComplete)
		if !hasUsableResults {
			// Preserve a more specific error that completed before the deadline.
			// Deadline-derived probe errors still classify as timeouts.
			if allTracerouteRunsFailedErr != nil {
				return nil, false, allTracerouteRunsFailedErr
			}
			return nil, false, context.DeadlineExceeded
		}
		if !params.ReturnPartialResults {
			return nil, false, context.DeadlineExceeded
		}
		results.TimedOut = true
		return &results, e2eComplete, nil
	}

	// Only fail if all traceroute runs failed
	if allTracerouteRunsFailedErr != nil {
		return nil, false, allTracerouteRunsFailedErr
	}
	if len(tracerouteErrors) > 0 {
		log.Warnf("Some traceroute runs failed (%d/%d): %v", len(tracerouteErrors), params.TracerouteQueries, errors.Join(tracerouteErrors...))
	}
	return &results, e2eComplete, nil
}

// e2eQueriesDelay computes the delay to wait between successive e2e probe queries,
// capped at 1 second so a large query count or timeout doesn't stall the run for too
// long between probes.
//
// When TotalTimeout is set, the delay spreads launches across 90% of the run budget
// after reserving enough time for the final probe's per-probe timeout. The remaining
// 10% is reserved for test-level work outside the E2E probe response windows. A
// simultaneously configured Timeout independently caps each individual probe.
// Otherwise it falls back to the legacy estimate based on the per-call Timeout and
// MaxTTL, kept for callers that only set the per-call Timeout.
func e2eQueriesDelay(params TracerouteParams) time.Duration {
	var delay time.Duration
	if params.TotalTimeout > 0 {
		if params.E2eQueries <= 1 {
			return 0
		}
		// Calculate TotalTimeout * 9 / 10 without overflowing for durations near
		// time.Duration's upper bound.
		testProbeBudget := params.TotalTimeout/10*9 + (params.TotalTimeout%10)*9/10
		pacingBudget := testProbeBudget - effectiveProbeTimeout(params)
		if pacingBudget > 0 {
			delay = pacingBudget / time.Duration(params.E2eQueries-1)
		}
	} else {
		delay = (time.Duration(params.MaxTTL) * effectiveProbeTimeout(params)) / time.Duration(params.E2eQueries)
	}
	if delay > 1*time.Second {
		delay = 1 * time.Second
	}
	return delay
}

// deduplicateErrors returns a subset of errs with unique .Error() messages,
// preserving the order of first occurrence.
func deduplicateErrors(errs []error) []error {
	seen := make(map[string]struct{}, len(errs))
	unique := make([]error, 0, len(errs))
	for _, err := range errs {
		msg := err.Error()
		if _, ok := seen[msg]; !ok {
			seen[msg] = struct{}{}
			unique = append(unique, err)
		}
	}
	return unique
}
