package cmd

import "time"

type TracerouteParams struct {
	Hostname        string
	Protocol        string
	TracerouteCount int
	MinTTL          int
	MaxTTL          int
	Delay           int
	Timeout         time.Duration
	TCPMethod       string
	DestinationPort int
	WantV6          bool
}
