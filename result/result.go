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
		E2eProbe   E2eProbe   `json:"e2e_probe"`
	}

	// E2eProbe contains e2e probe results
	E2eProbe struct {
		RTTs                 []float64   `json:"rtts"`
		PacketsSent          int         `json:"packets_sent"`
		PacketsReceived      int         `json:"packets_received"`
		PacketLossPercentage float32     `json:"packet_loss_percentage"`
		Jitter               float64     `json:"jitter"`
		RTT                  E2eProbeRTT `json:"rtt"`
	}

	// E2eProbeRTT contains e2e latency stats
	E2eProbeRTT struct {
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
	}

	// TracerouteHop encapsulates information about a single
	// hop in a traceroute
	TracerouteHop struct {
		TTL       int     `json:"ttl"`
		IPAddress net.IP  `json:"ip_address"`
		RTT       float64 `json:"rtt"`
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
	r.E2eProbe.RTTs = []float64{}

	// TODO: Replace with "50x e2e probe impl"
	//       Right now, we temporarily use single Traceroute data to fill e2e probe
	if len(r.Traceroute.Runs) == 0 {
		return
	}
	tracerouteRun := r.Traceroute.Runs[0]

	r.E2eProbe.PacketsSent = 1

	destHop := tracerouteRun.getDestinationHop()
	if destHop == nil {
		r.E2eProbe.PacketLossPercentage = 1
		return
	}
	r.E2eProbe.RTT.Avg = destHop.RTT
	r.E2eProbe.RTT.Min = destHop.RTT
	r.E2eProbe.RTT.Max = destHop.RTT
	r.E2eProbe.PacketsReceived = 1
	r.E2eProbe.PacketLossPercentage = 0
	r.E2eProbe.RTTs = []float64{destHop.RTT}
}

func (tr *TracerouteRun) getDestinationHop() *TracerouteHop {
	for _, hop := range tr.Hops {
		if hop.IsDest {
			return hop
		}
	}
	return nil
}
