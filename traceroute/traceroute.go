package traceroute

import (
	"context"

	"github.com/DataDog/datadog-traceroute/cache"
	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/publicip"
	"github.com/DataDog/datadog-traceroute/result"
)

type Traceroute struct {
	publicIPFetcher *publicip.PublicIPFetcher
}

func NewTraceroute(cacheType cache.CacheType) (*Traceroute, error) {
	cache, err := cache.NewCache(cacheType)
	if err != nil {
		return nil, err
	}
	fetcher := publicip.NewPublicIPFetcher(cache)
	return &Traceroute{
		publicIPFetcher: fetcher,
	}, nil
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
	ip, err := t.publicIPFetcher.GetIP()
	if err != nil {
		return nil, err
	}

	// TODO: TEST ME
	results.Source.PublicIP = ip.String()

	return results, nil
}
