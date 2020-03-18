package doorstopper

import (
	"errors"
	"io"
	"io/ioutil"
	"strings"
	"testing"
)

type MockRunner string

type PipeErrorRunner string

type RunErrorRunner string

var mockIptablesList = MockRunner(`Chain PREROUTING (policy ACCEPT)
target     prot opt source               destination         
REDIRECT   udp  --  0.0.0.0/0            192.168.0.202        udp dpt:16683 redir ports 51820
REDIRECT   udp  --  0.0.0.0/0            192.168.0.203        udp dpt:15409 redir ports 51820
REDIRECT   udp  --  0.0.0.0/0            192.168.0.204        udp dpt:15409 redir ports 51820
`)

func (mock MockRunner) StdoutPipe() (io.ReadCloser, error) {
	return ioutil.NopCloser(strings.NewReader(string(mock))), nil
}

func (mock MockRunner) Run() error {
	return nil
}

func (mock PipeErrorRunner) StdoutPipe() (io.ReadCloser, error) {
	return nil, errors.New(string(mock))
}

func (mock PipeErrorRunner) Run() error {
	return nil
}

func (mock RunErrorRunner) StdoutPipe() (io.ReadCloser, error) {
	return nil, errors.New(string(mock))
}

func (mock RunErrorRunner) Run() error {
	return errors.New(string(mock))
}

func createMockRunner(output string, pipeError error, runError error) Runner {
	return MockRunner(output)
}

func TestRemoveRedirect(t *testing.T) {
	touched := false
	mockIptables := func(args ...string) Runner {
		if args[2] == "-L" {
			return mockIptablesList
		} else if args[2] == "-D" {
			touched = true
			if args[4] != "2" {
				t.Fatal("Wrong rule number received: ", args[4])
			}
			return createMockRunner("", nil, nil)
		} else {
			t.Fatal("Wrong arguments received: ", args)
			return nil
		}
	}

	err := removeRedirect(mockIptables, "192.168.0.203", 15409, 51820)
	if err != nil {
		t.Fatal(err)
	}
	if !touched {
		t.Fatal("Not removed")
	}
}

func TestRemoveNonExistingRedirect(t *testing.T) {
	mockIptables := func(args ...string) Runner {
		if args[2] == "-L" {
			return mockIptablesList
		} else {
			t.Fatal("Wrong arguments received: ", args)
			return nil
		}
	}

	err := removeRedirect(mockIptables, "192.168.0.203", 15999, 51820)
	if err != nil {
		t.Fatal(err)
	}
}
