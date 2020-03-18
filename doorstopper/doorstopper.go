package doorstopper

import "time"

type DoorStopper struct {
	Protocol    string
	StopperPort int
	StunHost    string
	StunPort    int
	ExposedHost string
	ExposedPort int
	LocalHost   string
	LocalPort   int
	Iptables    string
	Interval    time.Duration
}
