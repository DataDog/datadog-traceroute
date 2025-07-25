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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedJitter, computeJitter(tt.rtts), tt.name)
		})
	}
}
