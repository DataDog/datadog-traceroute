package traceroute

import (
	"time"
)

type TracerouteParams struct {
	Hostname                  string
	Port                      int
	Protocol                  string
	MinTTL                    int
	MaxTTL                    int
	Delay                     int
	Timeout                   time.Duration
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
