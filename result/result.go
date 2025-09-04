package result

import (
	"net"

	"github.com/google/uuid"
)

type (
	// Results all the results from a single test run
	Results struct {
		Params     Params     `json:"params"`
		Traceroute Traceroute `json:"traceroute"`
		E2eProbe   *E2eProbe  `json:"e2e_probe"`
		Tags       []string   `json:"tags"`
	}

	// E2eProbe contains e2e probe results
	E2eProbe struct {
		Rtts                 []float64          `json:"rtts"`
		PacketsSent          int                `json:"packets_sent"`
		PacketsReceived      int                `json:"packets_received"`
		PacketLossPercentage float32            `json:"packet_loss_percentage"`
		Jitter               float64            `json:"jitter"`
		Rtt                  E2eProbeRttLatency `json:"rtt"`
	}

	// E2eProbeRttLatency contains e2e latency stats
	E2eProbeRttLatency struct {
		Avg float64 `json:"avg"`
		Min float64 `json:"min"`
		Max float64 `json:"max"`
	}

	// HopCountStats contains hop count stats
	HopCountStats struct {
		Avg float64 `json:"avg"`
		Min int     `json:"min"`
		Max int     `json:"max"`
	}

	// Traceroute contains traceroute results
	Traceroute struct {
		Runs     []TracerouteRun `json:"runs"`
		HopCount HopCountStats   `json:"hop_count"`
	}

	// TracerouteRun contains traceroute results for a single run
	TracerouteRun struct {
		RunID       string                `json:"run_id"`
		Source      TracerouteSource      `json:"source"`
		Destination TracerouteDestination `json:"destination"`
		Hops        []*TracerouteHop      `json:"hops"`
		E2eProbe    *E2eProbe             `json:"e2e_probe"`
	}

	// TracerouteHop encapsulates information about a single
	// hop in a traceroute
	TracerouteHop struct {
		TTL       int     `json:"ttl"`
		IPAddress net.IP  `json:"ip_address"`
		Rtt       float64 `json:"rtt"`
		Reachable bool    `json:"reachable"`

		// Internal use
		IsDest bool `json:"-"`

		// DEPRECATED: In separate PR, remove fields below and its usage
		Port     uint16 `json:"-"`
		ICMPType uint8  `json:"-"`
		ICMPCode uint8  `json:"-"`
	}
	// TracerouteSource contains result source info
	TracerouteSource struct {
		// TODO: FIX ME, use string instead of net.IP
		IPAddress net.IP `json:"ip_address"`
		Port      uint16 `json:"port"`
	}

	// TracerouteDestination contains result destination info
	TracerouteDestination struct {
		IPAddress net.IP `json:"ip_address"`
		Port      uint16 `json:"port"`
	}
	// Params contains destination param info
	Params struct {
		Protocol string `json:"protocol"`
		Hostname string `json:"hostname"`
		Port     int    `json:"port"`
	}
)

func NewE2eProbe(packetsSent int, rtts []float64) *E2eProbe {
	// TODO: TEST ME
	minRtt := 0.0
	maxRtt := 0.0
	totalRtt := 0.0
	for _, rtt := range rtts {
		if rtt < minRtt || maxRtt == 0.0 {
			minRtt = rtt
		}
		if rtt > maxRtt {
			maxRtt = rtt
		}
		totalRtt += rtt
	}
	packetsReceived := len(rtts)
	return &E2eProbe{
		PacketsReceived:      packetsReceived,
		PacketsSent:          packetsSent,
		PacketLossPercentage: float32(packetsReceived) / float32(packetsSent),
		Jitter:               0,
		Rtt: E2eProbeRttLatency{
			Avg: totalRtt / float64(len(rtts)),
			Min: minRtt,
			Max: maxRtt,
		},
		Rtts: rtts,
	}
}

// Normalize results
func (r *Results) Normalize() {
	r.normalizeTracerouteRuns()
	r.normalizeTracerouteHops()
	r.normalizeE2eProbe()
}

func (r *Results) normalizeTracerouteRuns() {
	for i := range r.Traceroute.Runs {
		r.Traceroute.Runs[i].RunID = uuid.New().String()
	}
}

func (r *Results) normalizeTracerouteHops() {
	var hopCounts []int
	for _, run := range r.Traceroute.Runs {
		hopCount := len(run.Hops)
		for i := len(run.Hops) - 1; i >= 0; i-- {
			hop := run.Hops[i]
			if !hop.IPAddress.Equal(net.IP{}) {
				hopCount = i + 1
				break
			}
		}
		hopCounts = append(hopCounts, hopCount)
	}
	var hopsAvg float64
	var hopsMin, hopsMax int
	var totalHopCount int
	for _, hopsCount := range hopCounts {
		if hopsCount < hopsMin || hopsMin == 0 {
			hopsMin = hopsCount
		}
		if hopsCount > hopsMax {
			hopsMax = hopsCount
		}
		totalHopCount += hopsCount
	}
	hopsAvg = float64(totalHopCount) / float64(len(hopCounts))

	r.Traceroute.HopCount.Avg = hopsAvg
	r.Traceroute.HopCount.Min = hopsMin
	r.Traceroute.HopCount.Max = hopsMax
}

func (r *Results) normalizeE2eProbe() {
	var allRtts []float64
	var totalReceived int
	for i := range r.Traceroute.Runs {
		run := &r.Traceroute.Runs[i]
		run.RunID = uuid.New().String()

		destHop := run.getDestinationHop()
		packetReceived := 0
		var rtts []float64
		if destHop != nil {
			packetReceived = 1
			rtts = []float64{destHop.Rtt}
		}
		run.E2eProbe = NewE2eProbe(packetReceived, rtts)

		allRtts = append(allRtts, rtts...)
		totalReceived += packetReceived
	}
	r.E2eProbe = NewE2eProbe(totalReceived, allRtts)
}

func (tr *TracerouteRun) getDestinationHop() *TracerouteHop {
	for _, hop := range tr.Hops {
		if hop.IsDest {
			return hop
		}
	}
	return nil
}
