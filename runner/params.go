package runner

import (
	"time"

	"github.com/DataDog/datadog-traceroute/traceroute"
)

type TracerouteParams struct {
	Hostname                  string
	Protocol                  string
	TracerouteCount           int
	MinTTL                    int
	MaxTTL                    int
	Delay                     int
	Timeout                   time.Duration
	TCPMethod                 traceroute.TCPMethod
	DestinationPort           int
	WantV6                    bool
	TCPSynParisTracerouteMode bool
}
