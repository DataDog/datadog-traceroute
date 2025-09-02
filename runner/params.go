package runner

import (
	"time"

	"github.com/DataDog/datadog-traceroute/common"
)

type TracerouteParams struct {
	Hostname                  string
	Protocol                  string
	TracerouteCount           int
	MinTTL                    int
	MaxTTL                    int
	Delay                     int
	Timeout                   time.Duration
	TCPMethod                 common.TCPMethod
	DestinationPort           int
	WantV6                    bool
	TCPSynParisTracerouteMode bool
}
