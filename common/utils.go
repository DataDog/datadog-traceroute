package common

import (
	"time"

	"github.com/DataDog/datadog-traceroute/log"
)

func ConvertDurationToMs(duration time.Duration) float64 {
	seconds := duration.Seconds()
	milliseconds := seconds * 1000
	log.Debugf("ConvertDurationToMs: duration=%v (nanoseconds=%d) seconds=%f milliseconds=%f", 
		duration, duration.Nanoseconds(), seconds, milliseconds)
	return milliseconds
}
