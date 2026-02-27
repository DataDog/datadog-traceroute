package traceroute

import (
	"context"
	"errors"
	"sync"
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
	fetcher := publicip.NewPublicIPFetcher()
	return &Traceroute{
		publicIPFetcher: fetcher,
	}
}

func (t Traceroute) RunTraceroute(ctx context.Context, params TracerouteParams) (*result.Results, error) {
	log.Infof("Running traceroute with params: %+v", params)

	destinationPort := params.Port
	if destinationPort == 0 {
		destinationPort = common.DefaultPort
	}

	results, err := t.runTracerouteMulti(ctx, params, destinationPort)
	if err != nil {
		return nil, err
	}

	results.Protocol = params.Protocol
	results.Destination = result.Destination{
		Hostname: params.Hostname,
		Port:     destinationPort,
	}
	if params.ReverseDns {
		results.EnrichWithReverseDns()
	}
	results.Normalize()
	if params.SkipPrivateHops {
		results.RemovePrivateHops()
	}

	return results, nil
}

func (t Traceroute) runTracerouteMulti(ctx context.Context, params TracerouteParams, destinationPort int) (*result.Results, error) {
	var wg sync.WaitGroup
	var results result.Results
	var tracerouteErrors []error
	resultsAndErrorsMu := &sync.Mutex{}

	// regular traceroutes
	for i := 0; i < params.TracerouteQueries; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			trRun, err := runTracerouteOnceFn(ctx, params, destinationPort)
			resultsAndErrorsMu.Lock()
			if err != nil {
				tracerouteErrors = append(tracerouteErrors, err)
			} else {
				results.Traceroute.Runs = append(results.Traceroute.Runs, *trRun)
			}
			resultsAndErrorsMu.Unlock()
		}()
	}

	if params.E2eQueries > 0 {
		// e2eQueriesDelay is currently calculated based on "MaxTTL * Timeout / e2e queries"
		// but should be replaced by "Timeout / e2e queries" once we change the meaning of Timeout param to be global vs per call.
		// Related Jira ticket: CNM-4763 datadog-traceroute library should provide global timeout option instead of per call
		e2eQueriesDelay := (time.Duration(params.MaxTTL) * params.Timeout) / time.Duration(params.E2eQueries)
		if e2eQueriesDelay > 1*time.Second {
			e2eQueriesDelay = 1 * time.Second
		}
		log.Tracef("e2e query delay: %d msec", e2eQueriesDelay.Milliseconds())

		// e2e probes
		for i := 0; i < params.E2eQueries; i++ {
			log.Tracef("send e2e probe #%d", i+1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				e2eRtt, err := runE2eProbeOnce(ctx, params, destinationPort)
				resultsAndErrorsMu.Lock()
				if err != nil {
					log.Debugf("E2E probe error (recorded as 0 RTT): %s", err)
					results.E2eProbe.RTTs = append(results.E2eProbe.RTTs, 0.0)
				} else {
					results.E2eProbe.RTTs = append(results.E2eProbe.RTTs, e2eRtt)
				}
				resultsAndErrorsMu.Unlock()
			}()
			if i < (params.E2eQueries - 1) { // don't add delay for last query
				time.Sleep(e2eQueriesDelay)
			}
		}
	}

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

			resultsAndErrorsMu.Lock()
			defer resultsAndErrorsMu.Unlock()
			results.Source.PublicIP = ip.String()
		}()
	}

	wg.Wait()

	// Only fail if all traceroute runs failed
	if params.TracerouteQueries > 0 && len(results.Traceroute.Runs) == 0 && len(tracerouteErrors) > 0 {
		return nil, errors.Join(deduplicateErrors(tracerouteErrors)...)
	}
	if len(tracerouteErrors) > 0 {
		log.Warnf("Some traceroute runs failed (%d/%d): %v", len(tracerouteErrors), params.TracerouteQueries, errors.Join(tracerouteErrors...))
	}
	return &results, nil
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
