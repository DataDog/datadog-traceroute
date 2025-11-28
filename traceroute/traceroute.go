package traceroute

import (
	"context"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/log"
	"github.com/DataDog/datadog-traceroute/publicip"
	"github.com/DataDog/datadog-traceroute/result"
)

type Traceroute struct {
	publicIPFetcher *publicip.PublicIPFetcher
}

func NewTraceroute() *Traceroute {
	fetcher := publicip.NewPublicIPFetcher()
	return &Traceroute{
		publicIPFetcher: fetcher,
	}
}

func (t Traceroute) RunTraceroute(ctx context.Context, params TracerouteParams) (*result.Results, error) {
	// TODO: TEST ME

	destinationPort := params.Port
	if destinationPort == 0 {
		destinationPort = common.DefaultPort
	}

	results, err := runTracerouteMulti(ctx, params, destinationPort)
	if err != nil {
		return nil, err
	}

	results.Protocol = params.Protocol
	results.Destination = result.Destination{
		Hostname: params.Hostname,
		Port:     destinationPort,
	}
	if params.ReverseDns {
		results.EnrichWithReverseDns()
	}
	results.Normalize()
	if params.SkipPrivateHops {
		results.RemovePrivateHops()
	}

	if params.CollectSourcePublicIP {
		// TODO: should be done concurrently
		// TODO: TEST ME
		ip, err := t.publicIPFetcher.GetIP()
		if err != nil {
			log.Debugf("Error getting IP: %s", err)
		} else {
			results.Source.PublicIP = ip.String()
		}
	}
	return results, nil
}
