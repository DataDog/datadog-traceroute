package cmd

import "time"

type TracerouteParams struct {
	hostname  string
	protocol  string
	npaths    int
	minTTL    int
	maxTTL    int
	delay     int
	timeout   time.Duration
	tcpmethod string
	dport     int
	wantV6    bool
}
