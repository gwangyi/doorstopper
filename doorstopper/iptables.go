package doorstopper

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/golang/glog"
	"io"
	"io/ioutil"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

var whitespaces = regexp.MustCompile(`\s+`)

type Runner interface {
	StdoutPipe() (io.ReadCloser, error)
	Run() error
}

type RunnerFactory func(args ...string) Runner

func createRunnerFactory(cmd []string) RunnerFactory {
	return func(args ...string) Runner {
		return exec.Command(cmd[0], append(cmd[1:], args...)...)
	}
}

func removeRedirect(iptables RunnerFactory, localIP string, stopperPort, localPort int) (err error) {
	glog.V(2).Info("Run iptables -L")
	cmd := iptables(
		"-t", "nat",
		"-L", "PREROUTING",
		"-n")
	reader, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	defer reader.Close()
	bufrd := bufio.NewReader(reader)
	linenumberChan := make(chan int)
	errChan := make(chan error)

	portString := fmt.Sprintf("dpt:%d", stopperPort)

	go func() {
		// Discard first two lines
		bufrd.ReadString('\n')
		bufrd.ReadString('\n')
		linenumber := 1
		for {
			line, err := bufrd.ReadString('\n')
			if err != nil {
				glog.V(2).Infof("Read error from iptables -L: %v", err)
				errChan <- err
				return
			}
			row := whitespaces.Split(line, 6)
			if len(row) >= 6 &&
				strings.Contains(row[1], "udp") &&
				row[4] == localIP &&
				strings.Contains(row[5], portString) {
				linenumberChan <- linenumber
				io.Copy(ioutil.Discard, bufrd)
				return
			}
			linenumber += 1
		}
	}()

	if err := cmd.Run(); err != nil {
		return err
	}

	select {
	case ln := <-linenumberChan:
		glog.V(1).Infof("Rule number: %d", ln)
		glog.V(1).Info("Run iptables -D")
		cmd := iptables(
			"-t", "nat",
			"-D", "PREROUTING", strconv.Itoa(ln))

		if err := cmd.Run(); err != nil {
			return err
		}
		return nil
	case err = <-errChan:
		if err.Error() == "EOF" {
			return nil
		}
		return
	}
}

func addRedirect(iptables RunnerFactory, iface, localIP string, stopperPort, localPort int) (err error) {
	glog.V(2).Info("Run iptables -A")
	cmd := iptables(
		"-t", "nat",
		"-A", "PREROUTING",
		"-p", "udp",
		"-i", iface,
		"-d", localIP,
		"--dport", strconv.Itoa(stopperPort),
		"-j", "REDIRECT",
		"--to-ports", strconv.Itoa(localPort))
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func getInterfaceNameFromAddr(localHost string) (name string, err error) {
	ip := net.ParseIP(localHost)
	if ip == nil {
		err = errors.New("Failed to parse host name")
		return
	}

	glog.V(2).Info("Listing interfaces")
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		glog.V(2).Infof("Finding addresses in interface %s", iface.Name)
		addrs, err := iface.Addrs()
		if err != nil {
			glog.Errorf("Failed to getting address for interface %s: %v", iface.Name, err)
			continue
		}
		glog.V(2).Infof("Addresses: %#v", addrs)

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if ok && ipnet.IP.Equal(ip) {
				glog.V(2).Infof("Interface %s matches", iface.Name)
				name = iface.Name
				return name, nil
			}
		}
	}

	err = errors.New("Interface is not found")
	return
}

func (doorStopper *DoorStopper) RemoveRedirect() (err error) {
	ip := net.ParseIP(doorStopper.LocalHost)
	if ip == nil {
		err = errors.New("Failed to parse host name")
		return
	}
	ipString := ip.String()
	err = removeRedirect(
		createRunnerFactory(doorStopper.Iptables),
		ipString,
		doorStopper.StopperPort,
		doorStopper.LocalPort)
	return
}

func (doorStopper *DoorStopper) AddRedirect() (err error) {
	ip := net.ParseIP(doorStopper.LocalHost)
	if ip == nil {
		err = errors.New("Failed to parse host name")
		return
	}
	ipString := ip.String()
	iface, err := getInterfaceNameFromAddr(doorStopper.LocalHost)
	if err != nil {
		return
	}
	err = addRedirect(
		createRunnerFactory(doorStopper.Iptables),
		iface,
		ipString,
		doorStopper.StopperPort,
		doorStopper.LocalPort)
	return
}
