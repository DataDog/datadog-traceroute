package runner

import (
	"time"

	"github.com/DataDog/datadog-traceroute/traceroute"
)

type TracerouteParams struct {
	Hostname                  string
	Port                      int
	Protocol                  string
	MinTTL                    int
	MaxTTL                    int
	Delay                     int
	Timeout                   time.Duration
	TCPMethod                 traceroute.TCPMethod
	WantV6                    bool
	TCPSynParisTracerouteMode bool
	ReverseDns                bool
	TracerouteQueries         int
	E2eQueries                int
	UseWindowsDriver          bool
	SkipPrivateHops           bool
}
