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

const ipCheckerCallTimeout = 2 * time.Second

// ipCheckers list of reliable public IP checkers
var ipCheckers = []string{
	"https://icanhazip.com/",         // owned by cloudflare
	"https://ipinfo.io/ip",           // same as our GeoIP info provider
	"https://checkip.amazonaws.com/", // Amazon
	"https://api.ipify.org/",         // Dedicated Public IP info and GeoIP info provider
	"https://whatismyip.akamai.com/", // Akamai is a CDN Provider
}

func GetPublicIP(ctx context.Context, client *http.Client, backoffPolicy *backoff.ExponentialBackOff) (net.IP, error) {
	for _, ipChecker := range ipCheckers {
		ip, err := getPublicIPUsingIPChecker(ctx, client, backoffPolicy, ipChecker)
		if err != nil {
			log.Debugf("error fetching: %s, %s\n", ipChecker, err.Error())
			continue
		}
		return ip, nil
	}
	return nil, errors.New("no IP found")
}

func getPublicIPUsingIPChecker(ctx context.Context, client *http.Client, backoffPolicy *backoff.ExponentialBackOff, dest string) (net.IP, error) {
	req, err := http.NewRequest("GET", dest, nil)
	if err != nil {
		return nil, errors.New("failed to create new request: " + err.Error())
	}

	operation := func() (net.IP, error) {
		return handleRequest(client, req)
	}
	ctxWithTimeout, cancel := context.WithTimeout(ctx, ipCheckerCallTimeout)
	defer cancel()
	result, err := backoff.Retry(ctxWithTimeout, operation, backoff.WithBackOff(backoffPolicy))
	if err != nil {
		return nil, errors.New("backoff retry error: " + err.Error())
	}

	return result, nil
}

func handleRequest(client *http.Client, req *http.Request) (net.IP, error) {
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
