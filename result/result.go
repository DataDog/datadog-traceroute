package result

import (
	"math"
	"net"

	"github.com/DataDog/datadog-traceroute/log"
	"github.com/DataDog/datadog-traceroute/reversedns"
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
		TTL        int      `json:"ttl"`
		IPAddress  net.IP   `json:"ip_address"`
		RTT        float64  `json:"rtt"`
		Reachable  bool     `json:"reachable"`
		ReverseDns []string `json:"reverse_dns,omitempty"`

		// Internal use
		IsDest bool `json:"-"`

		// DEPRECATED: In separate PR, remove fields below and its usage
		Port     uint16 `json:"-"`
		ICMPType uint8  `json:"-"`
		ICMPCode uint8  `json:"-"`
	}
	// TracerouteSource contains result source info
	TracerouteSource struct {
		IPAddress net.IP `json:"ip_address"`
		Port      uint16 `json:"port"`
	}

	// TracerouteDestination contains result destination info
	TracerouteDestination struct {
		IPAddress  net.IP   `json:"ip_address"`
		Port       uint16   `json:"port"`
		ReverseDns []string `json:"reverse_dns,omitempty"`
	}
	// Params contains destination param info
	Params struct {
		Protocol string `json:"protocol"`
		Hostname string `json:"hostname"`
		Port     int    `json:"port"`
	}
)

// EnrichWithReverseDns enrich results with reverse dns
func (r *Results) EnrichWithReverseDns() {
	for i := range r.Traceroute.Runs {
		run := &r.Traceroute.Runs[i]
		destRDns, err := reversedns.GetReverseDnsForIP(run.Destination.IPAddress)
		if err != nil {
			log.Debugf("failed to get reverse dns for destination IP: %s", err)
		} else {
			run.Destination.ReverseDns = destRDns
		}

		for j := range run.Hops {
			hop := run.Hops[j]
			hopRDns, err := reversedns.GetReverseDnsForIP(hop.IPAddress)
			if err != nil {
				log.Debugf("failed to get reverse dns for destination IP: %s", err)
			} else {
				hop.ReverseDns = hopRDns
			}
		}
	}
}

// Normalize results
func (r *Results) Normalize() {
	r.normalizeTracerouteRuns()
	r.normalizeTracerouteHops()
	r.normalizeTracerouteHopsCount()
	r.normalizeE2eProbe()
}

func (r *Results) normalizeTracerouteRuns() {
	for i := range r.Traceroute.Runs {
		r.Traceroute.Runs[i].RunID = uuid.New().String()
	}
}

func (r *Results) normalizeTracerouteHops() {
	for i, run := range r.Traceroute.Runs {
		for j, hop := range run.Hops {
			if !hop.IPAddress.Equal(net.IP{}) {
				r.Traceroute.Runs[i].Hops[j].Reachable = true
			}
		}
	}
}

func (r *Results) normalizeTracerouteHopsCount() {
	if len(r.Traceroute.Runs) == 0 {
		return
	}

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
	if len(r.E2eProbe.RTTs) == 0 {
		return
	}

	r.E2eProbe.PacketsSent = len(r.E2eProbe.RTTs)

	// Count received packets (non-zero RTTs) and collect valid RTTs
	var validRTTs []float64
	packetsReceived := 0

	for _, rtt := range r.E2eProbe.RTTs {
		if rtt > 0.0 {
			packetsReceived++
			validRTTs = append(validRTTs, rtt)
		}
	}

	r.E2eProbe.PacketsReceived = packetsReceived

	// Calculate packet loss percentage
	if r.E2eProbe.PacketsSent > 0 {
		r.E2eProbe.PacketLossPercentage = float32(r.E2eProbe.PacketsSent-r.E2eProbe.PacketsReceived) / float32(r.E2eProbe.PacketsSent)
	}

	if len(validRTTs) > 0 {
		var totalRTTs float64
		minRTT := validRTTs[0]
		maxRTT := validRTTs[0]

		for _, rtt := range validRTTs {
			totalRTTs += rtt
			if rtt < minRTT {
				minRTT = rtt
			}
			if rtt > maxRTT {
				maxRTT = rtt
			}
		}

		r.E2eProbe.RTT.Avg = totalRTTs / float64(len(validRTTs))
		r.E2eProbe.RTT.Min = minRTT
		r.E2eProbe.RTT.Max = maxRTT
	}

	r.E2eProbe.Jitter = calculateJitter(validRTTs)
}

// calculateJitter computes the average jitter from a slice of RTT measurements.
// Jitter is calculated as the mean absolute deviation of consecutive RTT differences.
func calculateJitter(rtts []float64) float64 {
	if len(rtts) < 2 {
		return 0.0 // Jitter requires at least 2 RTT measurements
	}

	var sumDiffs float64
	for i := 1; i < len(rtts); i++ {
		diff := math.Abs(rtts[i] - rtts[i-1])
		sumDiffs += diff
	}

	return sumDiffs / float64(len(rtts)-1)
}

func (tr *TracerouteRun) GetDestinationHop() *TracerouteHop {
	for _, hop := range tr.Hops {
		if hop.IsDest {
			return hop
		}
	}
	return nil
}
