package doorstopper

import (
	"fmt"
	"github.com/golang/glog"
	"gortc.io/stun"
	"io"
	"net"
	"sync"
	"time"
)

type holeKeeper struct {
	sock *net.UDPConn
	stop chan bool
	once sync.Once
	err  error
}

func (doorStopper *DoorStopper) keeper(sock *net.UDPConn, stop <-chan bool) {
	for {
		glog.V(2).Infof("Send dummy to %s:%d", doorStopper.ExposedHost, doorStopper.ExposedPort)
		raddr, err := net.ResolveUDPAddr(doorStopper.Protocol,
			fmt.Sprintf("%s:%d", doorStopper.ExposedHost, doorStopper.ExposedPort))
		if err == nil {
			_, err = sock.WriteToUDP([]byte{0}, raddr)
		}
		if err != nil {
			glog.Errorf("Unable to resolve host: %s:%d, %v",
				doorStopper.ExposedHost, doorStopper.ExposedPort, err.Error())
		}
		select {
		case <-time.After(doorStopper.Interval):
			break
		case <-stop:
			glog.V(1).Info("Stopped")
			return
		}
	}
}

func (keeper *holeKeeper) Close() (err error) {
	keeper.once.Do(keeper.close)
	return keeper.err
}

func (keeper *holeKeeper) close() {
	keeper.stop <- true
	close(keeper.stop)
	keeper.err = keeper.sock.Close()
}

func doStunSync(client *stun.Client, message *stun.Message) (response *stun.Message, err error) {
	errChan := make(chan error)
	messageChan := make(chan *stun.Message)

	go func() {
		if err = client.Do(message, func(res stun.Event) {
			defer close(errChan)
			defer close(messageChan)

			if res.Error != nil {
				errChan <- res.Error
			} else {
				messageChan <- res.Message
			}

		}); err != nil {
			close(errChan)
			close(messageChan)

			return
		}
	}()
	select {
	case response = <-messageChan:
		return
	case err = <-errChan:
		return
	}
}

func (doorStopper *DoorStopper) Penetrate() (keeper io.Closer, err error) {
	glog.V(2).Info("Create UDP socket for STUN")
	laddr, err := net.ResolveUDPAddr(doorStopper.Protocol, fmt.Sprintf(":%d", doorStopper.StopperPort))
	if err != nil {
		return
	}
	raddr, err := net.ResolveUDPAddr(doorStopper.Protocol, fmt.Sprintf("%s:%d", doorStopper.StunHost, doorStopper.StunPort))
	if err != nil {
		return
	}
	sock, err := net.DialUDP(doorStopper.Protocol, laddr, raddr)
	if err != nil {
		return
	}
	if err = doorStopper.doPenetrate(sock); err != nil {
		return
	}

	stop := make(chan bool)

	glog.V(2).Info("Create UDP socket for Hole Keeper")
	sock, err = net.ListenUDP(doorStopper.Protocol, laddr)
	if err != nil {
		return
	}
	go doorStopper.keeper(sock, stop)

	return &holeKeeper{sock: sock, stop: stop}, nil
}

func (doorStopper *DoorStopper) doPenetrate(sock *net.UDPConn) (err error) {
	glog.V(2).Info("Create STUN client")
	c, err := stun.NewClient(sock)
	if err != nil {
		return
	}
	defer c.Close()
	message, err := stun.Build(stun.TransactionID, stun.BindingRequest)
	if err != nil {
		return
	}
	glog.V(2).Info("Perform STUN event")
	response, err := doStunSync(c, message)

	var xorAddr stun.XORMappedAddress
	if err = xorAddr.GetFrom(response); err != nil {
		return
	}
	doorStopper.ExposedHost = xorAddr.IP.String()
	doorStopper.ExposedPort = xorAddr.Port
	glog.V(1).Infof("External Address: %s:%d", doorStopper.ExposedHost, doorStopper.ExposedPort)
	return
}
