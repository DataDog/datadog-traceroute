package result

import (
	"net"
)

type (
	// Results all the results from a single test run
	Results struct {
		Params     Params     `json:"params"`
		Traceroute Traceroute `json:"traceroute"`
		E2eProbe   E2eProbe   `json:"e2e_probe"`
		Tags       []string   `json:"tags"`
	}

	// E2eProbe TODO
	E2eProbe struct {
		Rtts                 []float64   `json:"rtts"`
		PacketsSent          int         `json:"packets_sent"`
		PacketsReceived      int         `json:"packets_received"`
		PacketLossPercentage float32     `json:"packet_loss_percentage"`
		Jitter               int         `json:"jitter"`
		Rtt                  E2eProbeRtt `json:"latency"`
	}

	E2eProbeRtt struct {
		Avg float64 `json:"avg"`
		Min float64 `json:"min"`
		Max float64 `json:"max"`
	}

	HopsStats struct {
		Avg float64 `json:"avg"`
		Min int     `json:"min"`
		Max int     `json:"max"`
	}

	// Traceroute TODO
	Traceroute struct {
		Runs []TracerouteRun `json:"runs"`
		Hops HopsStats       `json:"hops"`
	}

	// TracerouteRun TODO
	TracerouteRun struct {
		Source      TracerouteSource      `json:"source"`
		Destination TracerouteDestination `json:"destination"`
		Hops        []*TracerouteHop      `json:"hops"`
	}

	// TracerouteHop encapsulates information about a single
	// hop in a traceroute
	TracerouteHop struct {
		IP  string  `json:"ip"`
		RTT float64 `json:"rtt"`

		// DEPRECATED: In separate PR, remove fields below and its usage
		IsDest   bool   `json:"-"`
		Port     uint16 `json:"-"`
		ICMPType uint8  `json:"-"`
		ICMPCode uint8  `json:"-"`
	}
	// TracerouteSource contains result source info
	TracerouteSource struct {
		IP   net.IP `json:"ip"`
		Port uint16 `json:"port"`
	}

	// TracerouteDestination contains result destination info
	TracerouteDestination struct {
		IP   string `json:"ip"`
		Port uint16 `json:"port"`
	}
	// Params contains destination param info
	Params struct {
		Protocol string `json:"protocol"`
		Hostname string `json:"hostname"`
		Port     int    `json:"port"`
	}
)

func (r *Results) Normalize() {
	// build hops stats
	var hopCounts []int
	for _, run := range r.Traceroute.Runs {
		hopCount := 0
		for i, hop := range run.Hops {
			if hop.IP != "" {
				hopCount = i + 1
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

	r.Traceroute.Hops.Avg = hopsAvg
	r.Traceroute.Hops.Min = hopsMin
	r.Traceroute.Hops.Max = hopsMax
}
