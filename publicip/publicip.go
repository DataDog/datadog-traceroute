package publicip

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/DataDog/datadog-traceroute/cache"
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
	myIP, err := cache.GetWithExpiration("public_ip", func() ([]byte, error) {
		ip, err := GetPublicIP(p.client)
		fmt.Printf("[CACHE] GetPublicIP IP: %s\n", ip.String())
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
