package doorstopper

import (
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/golang/glog"
)

type EndpointInfo struct {
	Protocol string
	Host     string
	Port     int
}

type DoorStopperService interface {
	Configure(doorStopper *DoorStopper) error
	Start() error
	Stop() error
	Endpoint() EndpointInfo
}

type doorStopperServiceImpl struct {
	stopper DoorStopper
	keeper  io.Closer
}

func validateHost(host string) error {
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%#v is not a valid host name", host)
	}
	return nil
}

func (service *doorStopperServiceImpl) Configure(doorStopper *DoorStopper) (err error) {
	if doorStopper.Protocol != "udp" &&
		doorStopper.Protocol != "udp4" &&
		doorStopper.Protocol != "udp6" {
		return fmt.Errorf("Protocol %#v is not supported", doorStopper.Protocol)
	}
	if err = validateHost(doorStopper.LocalHost); err != nil {
		return
	}
	if doorStopper.LocalPort == 0 {
		return errors.New("Local port should be specified.")
	}
	if len(doorStopper.Iptables) == 0 {
		return errors.New("Iptables command should be specified.")
	}
	if doorStopper.Interval == 0 {
		return errors.New("Keeper interval should be specified.")
	}
	service.stopper = *doorStopper
	glog.V(1).Infof("Configuration: %#v", doorStopper)
	return
}

func (service *doorStopperServiceImpl) Start() (err error) {
	service.Stop()
	if err = service.stopper.RemoveRedirect(); err != nil {
		return
	}

	keeper, err := service.stopper.Penetrate()
	if err != nil {
		return
	}

	if err = service.stopper.AddRedirect(); err != nil {
		keeper.Close()
		return
	}

	service.keeper = keeper
	return
}

func (service *doorStopperServiceImpl) Stop() (err error) {
	if service.keeper != nil {
		keeper := service.keeper
		service.keeper = nil
		return keeper.Close()
	}
	return nil
}

func (service *doorStopperServiceImpl) Endpoint() EndpointInfo {
	if service.keeper == nil {
		return EndpointInfo{Protocol: ""}
	}
	return EndpointInfo{
		Protocol: service.stopper.Protocol,
		Host:     service.stopper.ExposedHost,
		Port:     service.stopper.ExposedPort,
	}
}

func CreateService(doorStopper *DoorStopper) (DoorStopperService, error) {
	service := &doorStopperServiceImpl{}
	err := service.Configure(doorStopper)
	if err != nil {
		return nil, err
	}
	return service, nil
}
