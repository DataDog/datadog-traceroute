package publicip

import (
	"net"
	"net/http"
	"time"

	"github.com/DataDog/datadog-traceroute/cache"
	"github.com/DataDog/datadog-traceroute/log"
)

const defaultPublicIPCacheExpiration = 2 * time.Hour

type PublicIPFetcher struct {
	client *http.Client
}

func NewPublicIPFetcher() *PublicIPFetcher {
	return &PublicIPFetcher{
		client: &http.Client{},
	}
}

func (p *PublicIPFetcher) GetIP() (net.IP, error) {
	myIP, err := cache.GetWithExpiration("source_public_ip", func() ([]byte, error) {
		ip, err := GetPublicIP(p.client)
		log.Debugf("Public IP fetched: %s", ip.String())
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
