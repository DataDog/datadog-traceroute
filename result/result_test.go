package result

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/DataDog/datadog-traceroute/reversedns"
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
				E2eProbe: E2eProbe{
					RTTs: []float64{20, 30, 40, 0, 30},
				},
			},
			ExpectedResults: Results{
				Traceroute: Traceroute{
					Runs: []TracerouteRun{
						{
							RunID: "id-0",
							Hops: []*TracerouteHop{
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 10, Reachable: true},
								{},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 30, Reachable: true},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 30, IsDest: true, Reachable: true},
							},
						},
						{
							RunID: "id-1",
							Hops: []*TracerouteHop{
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 10, Reachable: true},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 20, Reachable: true},
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
					RTTs:                 []float64{20, 30, 40, 0, 30},
					PacketsSent:          5,
					PacketsReceived:      4,
					PacketLossPercentage: 0.2,
					Jitter:               10,
					RTT: E2eProbeRTT{
						Avg: 30,
						Min: 20,
						Max: 40,
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
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 10, Reachable: true},
								{},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 30, Reachable: true},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 30, Reachable: true},
							},
						},
						{
							Hops: []*TracerouteHop{
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 10, Reachable: true},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 20, Reachable: true},
							},
						},
					},
				},
				E2eProbe: E2eProbe{
					RTTs: []float64{0, 0, 0, 0, 0},
				},
			},
			ExpectedResults: Results{
				Traceroute: Traceroute{
					Runs: []TracerouteRun{
						{
							RunID: "id-0",
							Hops: []*TracerouteHop{
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 10, Reachable: true},
								{},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 30, Reachable: true},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 30, Reachable: true},
							},
						},
						{
							RunID: "id-1",
							Hops: []*TracerouteHop{
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 10, Reachable: true},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 20, Reachable: true},
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
					RTTs:                 []float64{0, 0, 0, 0, 0},
					PacketsSent:          5,
					PacketsReceived:      0,
					PacketLossPercentage: 1,
					RTT:                  E2eProbeRTT{},
				},
			},
		},
		{
			name: "only traceroutes",
			Results: Results{
				Traceroute: Traceroute{
					Runs: []TracerouteRun{
						{
							Hops: []*TracerouteHop{
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 10, Reachable: true},
								{},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 30, Reachable: true},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 30, IsDest: true, Reachable: true},
							},
						},
					},
				},
				E2eProbe: E2eProbe{
					RTTs: []float64{},
				},
			},
			ExpectedResults: Results{
				Traceroute: Traceroute{
					Runs: []TracerouteRun{
						{
							RunID: "id-0",
							Hops: []*TracerouteHop{
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 10, Reachable: true},
								{},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 30, Reachable: true},
								{IPAddress: net.IP{10, 10, 10, 10}, RTT: 30, IsDest: true, Reachable: true},
							},
						},
					},
					HopCount: HopCountStats{
						Avg: 4,
						Min: 4,
						Max: 4,
					},
				},
				E2eProbe: E2eProbe{
					RTTs: []float64{},
				},
			},
		},
		{
			name: "only e2e probes",
			Results: Results{
				Traceroute: Traceroute{},
				E2eProbe: E2eProbe{
					RTTs: []float64{20, 30, 40, 0, 30},
				},
			},
			ExpectedResults: Results{
				Traceroute: Traceroute{},
				E2eProbe: E2eProbe{
					RTTs:                 []float64{20, 30, 40, 0, 30},
					PacketsSent:          5,
					PacketsReceived:      4,
					PacketLossPercentage: 0.2,
					Jitter:               10,
					RTT: E2eProbeRTT{
						Avg: 30,
						Min: 20,
						Max: 40,
					},
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

func TestResults_EnrichWithReverseDns(t *testing.T) {
	tests := []struct {
		name            string
		Results         Results
		ExpectedResults Results
	}{
		{
			name: "reverse dns for destination & hops",
			Results: Results{
				Traceroute: Traceroute{
					Runs: []TracerouteRun{
						{
							Hops: []*TracerouteHop{
								{IPAddress: net.IP{10, 10, 10, 10}},
								{IPAddress: net.IP{10, 10, 10, 11}},
							},
						},
						{
							Hops: []*TracerouteHop{
								{IPAddress: net.IP{10, 10, 10, 21}},
								{IPAddress: net.IP{10, 10, 10, 22}},
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
								{IPAddress: net.IP{10, 10, 10, 10}, ReverseDns: []string{"rdns-10.10.10.10"}},
								{IPAddress: net.IP{10, 10, 10, 11}, ReverseDns: []string{"rdns-10.10.10.11"}},
							},
						},
						{
							Hops: []*TracerouteHop{
								{IPAddress: net.IP{10, 10, 10, 21}, ReverseDns: []string{"rdns-10.10.10.21"}},
								{IPAddress: net.IP{10, 10, 10, 22}, ReverseDns: []string{"rdns-10.10.10.22"}},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reversedns.LookupAddrFn = func(_ context.Context, ip string) ([]string, error) {
				return []string{"rdns-" + ip}, nil
			}
			defer func() { reversedns.LookupAddrFn = net.DefaultResolver.LookupAddr }()

			tt.Results.EnrichWithReverseDns()
			assert.Equal(t, tt.ExpectedResults, tt.Results)
		})
	}
}

func TestCalculateJitter(t *testing.T) {
	tests := []struct {
		name     string
		rtts     []float64
		expected float64
	}{
		{
			name:     "empty slice",
			rtts:     []float64{},
			expected: 0.0,
		},
		{
			name:     "single RTT",
			rtts:     []float64{10.0},
			expected: 0.0,
		},
		{
			name:     "two identical RTTs",
			rtts:     []float64{10.0, 10.0},
			expected: 0.0,
		},
		{
			name:     "two different RTTs",
			rtts:     []float64{10.0, 20.0},
			expected: 10.0,
		},
		{
			name:     "three RTTs with consistent increase",
			rtts:     []float64{10.0, 20.0, 30.0},
			expected: 10.0, // |20-10| + |30-20| = 10 + 10 = 20, divided by 2 = 10
		},
		{
			name:     "three RTTs with varying differences",
			rtts:     []float64{10.0, 25.0, 20.0},
			expected: 10.0, // |25-10| + |20-25| = 15 + 5 = 20, divided by 2 = 10
		},
		{
			name:     "RTTs with decimal values",
			rtts:     []float64{12.1, 17.1, 22.1, 27.6, 23.1},
			expected: 5.0, // |17.1-12.1| + |22.1-17.1| + |27.6-22.1| + |23.1-27.6| = 5 + 5 + 5.5 + 4.5 = 20, divided by 4 = 5
		},
		{
			name:     "10 values equally increasing",
			rtts:     []float64{10, 15, 20, 25, 30, 35, 40, 45, 50, 55},
			expected: 5.0, // All differences are 5, so jitter = 5
		},
		{
			name:     "10 values equally decreasing",
			rtts:     []float64{100, 90, 80, 70, 60, 50, 40, 30, 20, 10},
			expected: 10.0, // All differences are 10 (absolute value), so jitter = 10
		},
		{
			name: "50 values",
			rtts: []float64{10, 20, 30, 20, 10, 20, 30, 20, 10, 20,
				10, 20, 30, 20, 10, 20, 30, 20, 10, 20,
				10, 20, 30, 20, 10, 20, 30, 20, 10, 20,
				10, 20, 30, 20, 10, 20, 30, 20, 10, 20,
				10, 20, 30, 20, 10, 20, 30, 20, 10, 20},
			expected: 10.0, // All differences are 10 (absolute value), so jitter = 10
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateJitter(tt.rtts)
			assert.Equal(t, tt.expected, result, "Jitter calculation mismatch for RTTs: %v", tt.rtts)
		})
	}
}
