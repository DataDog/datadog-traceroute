package common

import "time"

func ConvertDurationToMs(duration time.Duration) float64 {
	return duration.Seconds() * 1000
}
