package publicip

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/DataDog/datadog-traceroute/log"
	"github.com/cenkalti/backoff/v5"
)

// ipCheckers list of reliable public IP checkers
var ipCheckers = []string{
	"https://icanhazip.com/",         // owned by cloudflare
	"https://ipinfo.io/ip",           // same as our GeoIP info provider
	"https://checkip.amazonaws.com/", // Amazon
	"https://api.ipify.org/",         // Dedicated Public IP info and GeoIP info provider
	"https://whatismyip.akamai.com/", // Akamai is a CDN Provider
}

func GetPublicIP(client *http.Client) (net.IP, error) {
	// TODO: TEST ME
	for _, ipChecker := range ipCheckers {
		ip, err := doGetPublicIP(client, ipChecker)
		if err != nil {
			log.Debugf("error fetching: %s, %s\n", ipChecker, err.Error())
			continue
		}
		return ip, nil
	}
	return nil, errors.New("no IP found")
}

func doGetPublicIP(client *http.Client, dest string) (net.IP, error) {
	// TODO: TEST ME
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.InitialInterval = 500 * time.Millisecond
	expBackoff.MaxInterval = 3 * time.Second

	req, err := http.NewRequest("GET", dest, nil)
	if err != nil {
		return nil, errors.New("failed to create new request: " + err.Error())
	}

	operation := func() (net.IP, error) {
		resp, err := client.Do(req)
		if err != nil {
			return nil, errors.New("failed to fetch req: " + err.Error())
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, errors.New("failed to read content: " + err.Error())
		}

		// In case on non-retriable error, return Permanent error to stop retrying.
		// For this HTTP example, client errors are non-retriable.
		if resp.StatusCode == 400 {
			return nil, backoff.Permanent(errors.New("bad request"))
		}

		tb := strings.TrimSpace(string(body))
		ip := net.ParseIP(tb)
		if ip == nil {
			return nil, errors.New("IP address not valid: " + tb)
		}
		// Return successful response.
		return ip, nil
	}
	result, err := backoff.Retry(context.TODO(), operation, backoff.WithBackOff(expBackoff))
	if err != nil {
		return nil, errors.New("backoff retry error: " + err.Error())
	}

	return result, nil
}
