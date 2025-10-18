package publicip

import (
	"fmt"
	"net"
	"time"

	"github.com/DataDog/datadog-traceroute/cache"
	externalip "github.com/glendc/go-external-ip"
)

const defaultPublicIPCacheExpiration = 60 * time.Second

type PublicIPFetcher struct {
	cache *cache.Cache
}

func NewPublicIPFetcher(cache *cache.Cache) *PublicIPFetcher {
	return &PublicIPFetcher{
		cache: cache,
	}
}

func (p *PublicIPFetcher) GetIP() (net.IP, error) {
	myIP, err := p.cache.GetWithExpiration("public_ip", func() ([]byte, error) {
		ip, err := doGetIP()
		fmt.Printf("[CACHE] Get IP: %s\n", ip.String())
		if err != nil {
			return nil, err
		}
		return ip, nil
	}, defaultPublicIPCacheExpiration)

	if err != nil {
		return nil, err
	}

	return myIP, nil
}

func doGetIP() (net.IP, error) {
	// Create the default consensus,
	// using the default configuration and no logger.

	// TODO: fork externalip repository or copy the code in datadog-traceroute
	consensus := externalip.DefaultConsensus(nil, nil)

	// By default Ipv4 or Ipv6 is returned,
	// use the function below to limit yourself to IPv4,
	// or pass in `6` instead to limit yourself to IPv6.
	consensus.UseIPProtocol(4)

	// Get your IP,
	// which is never <nil> when err is <nil>.
	ip, err := consensus.ExternalIP()
	if err != nil {
		return nil, err
	}
	return ip, nil
}
