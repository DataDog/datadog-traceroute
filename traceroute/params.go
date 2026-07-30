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
	// Timeout caps each individual probe. A non-positive value is treated as
	// unset: it is derived from TotalTimeout and MaxTTL when TotalTimeout is
	// positive, or falls back to the legacy default otherwise.
	Timeout time.Duration
	// TotalTimeout bounds the entire RunTraceroute call, including DNS resolution,
	// all TracerouteQueries and E2eQueries, and enrichment. It is independent from
	// Timeout: when both are set, Timeout caps each probe while TotalTimeout caps the
	// complete call. Zero means no overall deadline is enforced.
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
	E2eQueries                int
	UseWindowsDriver          bool
	SkipPrivateHops           bool
}
