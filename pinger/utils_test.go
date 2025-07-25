package pinger

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_computeJitter(t *testing.T) {
	tests := []struct {
		name           string
		rtts           []time.Duration
		expectedJitter time.Duration
	}{
		{
			name: "simple case",
			rtts: []time.Duration{
				100 * time.Millisecond,
				150 * time.Millisecond,
				200 * time.Millisecond,
			},
			// (50+50)/2 = 50 ms
			expectedJitter: 50 * time.Millisecond,
		},
		{
			name:           "zero rtt",
			rtts:           []time.Duration{},
			expectedJitter: 0 * time.Millisecond,
		},
		{
			name: "one rtt",
			rtts: []time.Duration{
				100 * time.Millisecond,
			},
			expectedJitter: 0 * time.Millisecond,
		},
		{
			name: "two rtts",
			rtts: []time.Duration{
				100 * time.Millisecond,
				200 * time.Millisecond,
			},
			expectedJitter: 100 * time.Millisecond,
		},
		//{
		//	name: "test",
		//	rtts: []time.Duration{
		//		time.Duration(math.Floor(7.016214 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(8.151591 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(7.441048 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(8.043674 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(8.312216 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(9.263217 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(6.835798 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(8.031174 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(6.412464 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(7.990966 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(6.824257 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(8.763508 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(7.509465 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(8.066382 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(6.949507 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(8.902467 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(9.463634 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(8.754008 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(6.562797 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(9.24555 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(12.169011 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(10.074176 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(7.467174 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(9.087092 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(7.876924 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(9.686051 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(9.339175 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(7.20284 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(7.308006 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(7.496924 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(10.043759 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(8.487674 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(8.708383 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(8.404717 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(8.569716 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(8.042591 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(10.038801 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(8.420883 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(6.370422 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(8.105299 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(10.48076 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(11.221718 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(4.667463 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(8.716091 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(4.887296 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(7.425757 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(8.805341 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(7.901216 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(4.501379 * float64(time.Millisecond))),
		//		time.Duration(math.Floor(7.385131 * float64(time.Millisecond))),
		//	},
		//	expectedJitter: 100 * time.Millisecond,
		//},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedJitter, computeJitter(tt.rtts), tt.name)
		})
	}
}
