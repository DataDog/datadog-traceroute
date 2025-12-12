package common

import (
	"time"

	"github.com/DataDog/datadog-traceroute/log"
)

func ConvertDurationToMs(duration time.Duration) float64 {
	// Test Windows time.Now() precision by calling it twice in a row
	t1 := time.Now()
	t2 := time.Now()
	timeDiff := t2.Sub(t1)
	log.Debugf("ConvertDurationToMs: time.Now() precision test: t1=%v t2=%v diff=%v (%d ns)",
		t1, t2, timeDiff, timeDiff.Nanoseconds())

	seconds := duration.Seconds()
	milliseconds := seconds * 1000
	log.Debugf("ConvertDurationToMs: duration=%v (nanoseconds=%d) seconds=%f milliseconds=%f",
		duration, duration.Nanoseconds(), seconds, milliseconds)
	return milliseconds
}
