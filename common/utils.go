package common

import (
	"sync"
	"time"

	"github.com/DataDog/datadog-traceroute/log"
)

var (
	timePrecisionTestOnce sync.Once
)

func ConvertDurationToMs(duration time.Duration) float64 {
	// Test Windows time.Now() precision (only on first call)
	timePrecisionTestOnce.Do(func() {
		t1 := time.Now()
		t2 := t1
		iterations := 0

		// Keep calling time.Now() until we get a different value
		for t2.Equal(t1) && iterations < 1000000 {
			t2 = time.Now()
			iterations++
		}

		timeDiff := t2.Sub(t1)
		log.Debugf("ConvertDurationToMs: time.Now() precision test: t1=%v t2=%v diff=%v (%d ns) iterations=%d",
			t1, t2, timeDiff, timeDiff.Nanoseconds(), iterations)
	})

	seconds := duration.Seconds()
	milliseconds := seconds * 1000
	log.Debugf("ConvertDurationToMs: duration=%v (nanoseconds=%d) seconds=%f milliseconds=%f",
		duration, duration.Nanoseconds(), seconds, milliseconds)
	return milliseconds
}
