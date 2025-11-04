package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/DataDog/datadog-traceroute/common"
	"github.com/DataDog/datadog-traceroute/runner"
	"github.com/DataDog/datadog-traceroute/traceroute"
)

func tracerouteHandler(w http.ResponseWriter, req *http.Request) {

	//fmt.Fprintf(w, "tracerouteHandler\n")

	params := runner.TracerouteParams{
		Hostname:          "dns.google.com",
		Port:              443,
		Protocol:          strings.ToLower(string("tcp")),
		MinTTL:            1,
		MaxTTL:            30,
		Delay:             common.DefaultDelay,
		Timeout:           time.Duration(1) * time.Second,
		TCPMethod:         traceroute.TCPMethod("syn"),
		WantV6:            false,
		ReverseDns:        true,
		UseWindowsDriver:  true,
		TracerouteQueries: 3,
		E2eQueries:        50,

		//Hostname:          cfg.DestHostname,
		//Port:              int(cfg.DestPort),
		//Protocol:          strings.ToLower(string(cfg.Protocol)),
		//MinTTL:            trcommon.DefaultMinTTL,
		//MaxTTL:            int(cfg.MaxTTL),
		//Delay:             DefaultDelay,
		//Timeout:           timeout,
		//TCPMethod:         tracerouteHandler.TCPMethod(cfg.TCPMethod),
		//WantV6:            false,
		//ReverseDns:        cfg.ReverseDNS,
		//UseWindowsDriver:  !cfg.DisableWindowsDriver,
		//TracerouteQueries: cfg.TracerouteQueries,
		//E2eQueries:        cfg.E2eQueries,
	}

	results, err := runner.RunTraceroute(context.Background(), params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	marshal, err := json.Marshal(results)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(marshal)
	w.Write([]byte("\n"))
}

func headers(w http.ResponseWriter, req *http.Request) {

	for name, headers := range req.Header {
		for _, h := range headers {
			fmt.Fprintf(w, "%v: %v\n", name, h)
		}
	}
}

func main() {

	http.HandleFunc("/traceroute", tracerouteHandler)
	http.HandleFunc("/headers", headers)

	http.ListenAndServe(":8090", nil)
}
