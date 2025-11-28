package publicip

import (
	"context"
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
		client: buildHttpClient(),
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

func buildHttpClient() *http.Client {
	myDialer := net.Dialer{}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Note: we are forcing IPv4 for now to get shorter public_ip
		//       but if needed we can remove this custom `transport` and support both IPv4 and IPv6
		return myDialer.DialContext(ctx, "tcp4", addr)
	}
	client := &http.Client{Transport: transport}
	return client
}
