package publicip

import (
	"fmt"
	"net"
	"time"

	"github.com/DataDog/datadog-traceroute/cache"
)

const defaultPublicIPCacheExpiration = 2 * time.Hour

type PublicIPFetcher struct{}

func NewPublicIPFetcher() *PublicIPFetcher {
	return &PublicIPFetcher{}
}

func (p *PublicIPFetcher) GetIP() (net.IP, error) {
	myIP, err := cache.GetWithExpiration("public_ip", func() ([]byte, error) {
		ip, err := Get()
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
