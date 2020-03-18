package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/golang/glog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gwangyi/doorstopper/doorstopper"
)

var v4 = flag.Bool("4", true, "Use IPv4")
var v6 = flag.Bool("6", true, "Use IPv4")
var stopperPort = flag.Int("port", 15409, "Doorstopper local port")
var stunHost = flag.String("stun-host", "stun.l.google.com", "STUN server hostname")
var stunPort = flag.Int("stun-port", 19302, "STUN server port")
var localHost = flag.String("local-host", "", "Local service port")
var localPort = flag.Int("local-port", 51820, "Local service port")
var iptables = flag.String("iptables", "iptables", "iptables binary")
var interval = flag.Duration("interval", 5*time.Second, "Doorstopper packet interval")
var apiHost = flag.String("api-host", "localhost", "Hostname for API server")
var apiPort = flag.Int("api-port", 15409, "Port number for API server")

type EndpointInfo struct {
	Status   string
	Protocol string
	Host     string
	Port     int
}

type ErrorInfo struct {
	Status string
	Error  error
}

func handleError(w http.ResponseWriter, message error) {
	msg, err := json.Marshal(ErrorInfo{
		Status: "error",
		Error:  message,
	})
	if err != nil {
		http.Error(w,
			fmt.Sprintf(`{"status": "error", "error": %#v"}`, message),
			http.StatusInternalServerError)
	} else {
		http.Error(w,
			string(msg),
			http.StatusInternalServerError)
	}
}

func main() {
	flag.Parse()

	var protocol string
	if *v4 == *v6 {
		protocol = "udp"
	} else if *v4 {
		protocol = "udp4"
	} else {
		protocol = "udp6"
	}

	stopper := doorstopper.DoorStopper{
		Protocol:    protocol,
		StopperPort: *stopperPort,
		StunHost:    *stunHost,
		StunPort:    *stunPort,
		LocalHost:   *localHost,
		LocalPort:   *localPort,
		Iptables:    *iptables,
		Interval:    *interval,
	}

	if err := stopper.RemoveRedirect(); err != nil {
		glog.Fatal(err)
		return
	}

	keeper, err := stopper.Penetrate()
	if err != nil {
		glog.Fatal(err)
		return
	}

	if err := stopper.AddRedirect(); err != nil {
		glog.Fatal(err)
		return
	}

	defer func() {
		keeper.Close()
	}()

	quit := make(chan bool, 1)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	glog.V(1).Info("API server start")
	http.HandleFunc("/quit", func(w http.ResponseWriter, r *http.Request) {
		glog.V(2).Info("QUIT")
		fmt.Fprint(w, "QUIT")
		quit <- true
	})

	http.HandleFunc("/exposed", func(w http.ResponseWriter, r *http.Request) {
		glog.V(2).Info("exposed")
		w.Header().Add("Content-Type", "application/json")

		switch r.Method {
		case http.MethodPut:
			err = keeper.Close()
			if err != nil {
				glog.Error(err)
				handleError(w, err)
				return
			}

			if err = stopper.RemoveRedirect(); err != nil {
				glog.Error(err)
				handleError(w, err)
				return
			}

			keeper, err = stopper.Penetrate()
			if err != nil {
				glog.Error(err)
				handleError(w, err)
				return
			}

			if err = stopper.AddRedirect(); err != nil {
				glog.Error(err)
				handleError(w, err)
				return
			}
		}
		msg, err := json.Marshal(EndpointInfo{
			Status:   "ok",
			Protocol: stopper.Protocol,
			Host:     stopper.ExposedHost,
			Port:     stopper.ExposedPort,
		})
		if err != nil {
			handleError(w, err)
		} else {
			w.Write(msg)
		}
	})

	go http.ListenAndServe(fmt.Sprintf("%s:%d", *apiHost, *apiPort), nil)

	select {
	case <-stop:
	case <-quit:
	}
}
