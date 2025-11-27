package publicip

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v5"
)

// APIURIs is the URIs of the services.
var APIURIs = []string{
	"https://api.ipify.org",
	//"http://myexternalip.com/raw",
	//"http://ipinfo.io/ip",
	//"http://ipecho.net/plain",
	//"http://icanhazip.com",
	//"http://ifconfig.me/ip",
	//"http://ident.me",
	//"http://checkip.amazonaws.com",
	//"http://bot.whatismyipaddress.com",
	//"http://whatismyip.akamai.com",
	//"http://wgetip.com",
	//"http://ip.appspot.com",
	//"http://ip.tyk.nu",
	//"https://shtuff.it/myip/short",
}

func GetPublicIP(client *http.Client) (net.IP, error) {
	// TODO: TEST ME
	for _, d := range APIURIs {
		ip, err := doGetPublicIP(client, d)
		if err != nil {
			fmt.Printf("[GetPublicIP] error fetching: %s, %s\n", d, err.Error())
			continue
			//return nil, err
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

	//client := &http.Client{}

	//req, err := http.NewRequest("GET", dest, nil)
	//if err != nil {
	//	return nil, err
	//}
	//
	//for tries := 0; tries < MaxTries; tries++ {
	//	resp, err := client.Do(req)
	//	if err != nil {
	//		d := b.Duration()
	//		time.Sleep(d)
	//		continue
	//	}
	//
	//	defer resp.Body.Close()
	//
	//	body, err := ioutil.ReadAll(resp.Body)
	//	if err != nil {
	//		return nil, err
	//	}
	//
	//	if resp.StatusCode != 200 {
	//		return nil, errors.New(dest + " status code " + strconv.Itoa(resp.StatusCode) + ", body: " + string(body))
	//	}
	//
	//	tb := strings.TrimSpace(string(body))
	//	ip := net.ParseIP(tb)
	//	if ip == nil {
	//		return nil, errors.New("IP address not valid: " + tb)
	//	}
	//	return ip, nil
	//}

	req, err := http.NewRequest("GET", dest, nil)
	if err != nil {
		return nil, errors.New("failed to create new request: " + err.Error())
	}

	operation := func() (net.IP, error) {
		//resp, err := http.GetPublicIP(dest)
		//if err != nil {
		//	return nil, errors.New("failed to fetch req: " + err.Error())
		//}
		//defer resp.Body.Close()
		//body, err := ioutil.ReadAll(resp.Body)
		//if err != nil {
		//	return nil, errors.New("failed to read content: " + err.Error())
		//}

		fmt.Printf("[doGetPublicIP] client.Do: %v\n", req)
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

		// If we are being rate limited, return a RetryAfter to specify how long to wait.
		// This will also reset the backoff policy.
		if resp.StatusCode == 429 {
			seconds, err := strconv.ParseInt(resp.Header.Get("Retry-After"), 10, 64)
			if err == nil {
				return nil, backoff.RetryAfter(int(seconds))
			}
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
		fmt.Println("Errorx:", err)
		return nil, errors.New("backoff retry error: " + err.Error())
	}

	return result, nil
}
