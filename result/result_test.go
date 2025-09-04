package result

import (
	"fmt"
	"net"
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
			name: "normalize hops & e2e probes",
			Results: Results{
				Traceroute: Traceroute{
					Runs: []TracerouteRun{
						{
							Hops: []*TracerouteHop{
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 10},
								{},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 30},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 30, IsDest: true},
							},
						},
						{
							Hops: []*TracerouteHop{
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 10},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 20},
							},
						},
					},
				},
			},
			ExpectedResults: Results{
				Traceroute: Traceroute{
					Runs: []TracerouteRun{
						{
							RunID: "id-0",
							Hops: []*TracerouteHop{
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 10},
								{},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 30},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 30, IsDest: true},
							},
						},
						{
							RunID: "id-1",
							Hops: []*TracerouteHop{
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 10},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 20},
							},
						},
					},
					HopCount: HopCountStats{
						Avg: 3,
						Min: 2,
						Max: 4,
					},
				},
				E2eProbe: E2eProbe{
					RTTs:                 []float64{30},
					PacketsSent:          1,
					PacketsReceived:      1,
					PacketLossPercentage: 0,
					RTT: E2eProbeRTT{
						Avg: 30,
						Min: 30,
						Max: 30,
					},
				},
			},
		},
		{
			name: "destination not reachable",
			Results: Results{
				Traceroute: Traceroute{
					Runs: []TracerouteRun{
						{
							Hops: []*TracerouteHop{
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 10},
								{},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 30},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 30},
							},
						},
						{
							Hops: []*TracerouteHop{
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 10},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 20},
							},
						},
					},
				},
			},
			ExpectedResults: Results{
				Traceroute: Traceroute{
					Runs: []TracerouteRun{
						{
							RunID: "id-0",
							Hops: []*TracerouteHop{
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 10},
								{},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 30},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 30},
							},
						},
						{
							RunID: "id-1",
							Hops: []*TracerouteHop{
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 10},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 20},
							},
						},
					},
					HopCount: HopCountStats{
						Avg: 3,
						Min: 2,
						Max: 4,
					},
				},
				E2eProbe: E2eProbe{
					RTTs:                 []float64{},
					PacketsSent:          1,
					PacketsReceived:      0,
					PacketLossPercentage: 1,
					RTT:                  E2eProbeRTT{},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.Results.Normalize()
			for i := range tt.Results.Traceroute.Runs {
				assert.NotEmpty(t, tt.Results.Traceroute.Runs[i].RunID)
				tt.Results.Traceroute.Runs[i].RunID = fmt.Sprintf("id-%d", i)
			}
			assert.Equal(t, tt.ExpectedResults, tt.Results)
		})
	}
}
