package traceroute

import (
	"time"
)

type TracerouteParams struct {
	Hostname string
	Port     int
	Protocol string
	MinTTL   int
	MaxTTL   int
	Delay    int
	// Timeout caps each individual probe. Zero is treated as unset: it is derived
	// from TotalTimeout and MaxTTL when TotalTimeout is positive, or falls back to
	// the legacy default otherwise. Negative values are invalid.
	Timeout time.Duration
	// TotalTimeout bounds the entire RunTraceroute call, including DNS resolution,
	// all TracerouteQueries and E2eQueries, and enrichment. It is independent from
	// Timeout: when both are set, Timeout caps each probe while TotalTimeout caps the
	// complete call. Zero means no overall deadline is enforced. Polling drivers check
	// cancellation between blocking reads, so the call may return up to the default
	// 100 ms poll interval after this deadline; that bounded precision is intentional.
	TotalTimeout time.Duration
	// ReturnPartialResults allows RunTraceroute to return completed traceroute
	// runs with Results.TimedOut set when TotalTimeout expires. The default false
	// returns context.DeadlineExceeded and no results.
	ReturnPartialResults      bool
	TCPMethod                 TCPMethod
	WantV6                    bool
	TCPSynParisTracerouteMode bool
	ReverseDns                bool
	CollectSourcePublicIP     bool
	TracerouteQueries         int
	// E2eQueries are paced within 90% of TotalTimeout when it is set. Scheduling
	// reserves both the remaining 10% for test-level overhead and one complete
	// per-probe window for the final E2E packet.
	E2eQueries       int
	UseWindowsDriver bool
	SkipPrivateHops  bool
}
