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
	// Timeout caps each individual probe. Zero disables the per-probe deadline;
	// TotalTimeout, when set, still caps the complete call.
	Timeout time.Duration
	// TotalTimeout bounds the entire RunTraceroute call, including DNS resolution,
	// all TracerouteQueries and E2eQueries, and enrichment. It is independent from
	// Timeout: when both are set, Timeout caps each probe while TotalTimeout caps the
	// complete call. Zero means no overall deadline is enforced.
	TotalTimeout              time.Duration
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
