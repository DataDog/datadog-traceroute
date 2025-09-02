package result

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResults_Normalize(t *testing.T) {
	tests := []struct {
		name            string
		Results         Results
		ExpectedResults Results
	}{
		{
			name: "base case",
			Results: Results{
				Traceroute: Traceroute{
					Runs: []TracerouteRun{
						{
							Hops: []*TracerouteHop{
								{IP: "10.10.10.10", RTT: 10},
								{},
								{IP: "10.10.10.10", RTT: 30},
								{IP: "10.10.10.10", RTT: 30, IsDest: true},
							},
						},
						{
							Hops: []*TracerouteHop{
								{IP: "10.10.10.10", RTT: 10},
								{IP: "10.10.10.10", RTT: 20},
							},
						},
					},
				},
			},
			ExpectedResults: Results{
				Traceroute: Traceroute{
					Runs: []TracerouteRun{
						{
							Hops: []*TracerouteHop{
								{IP: "10.10.10.10", RTT: 10},
								{},
								{IP: "10.10.10.10", RTT: 30},
								{IP: "10.10.10.10", RTT: 30, IsDest: true},
							},
						},
						{
							Hops: []*TracerouteHop{
								{IP: "10.10.10.10", RTT: 10},
								{IP: "10.10.10.10", RTT: 20},
							},
						},
					},
					Hops: HopsStats{
						Avg: 3,
						Min: 2,
						Max: 4,
					},
				},
				E2eProbe: E2eProbe{
					Rtts:                 []float64{30},
					PacketsSent:          1,
					PacketsReceived:      1,
					PacketLossPercentage: 0,
					RttLatency: E2eProbeRttLatency{
						Avg: 30,
						Min: 30,
						Max: 30,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.Results.Normalize()
			assert.Equal(t, tt.ExpectedResults, tt.Results)
		})
	}
}
