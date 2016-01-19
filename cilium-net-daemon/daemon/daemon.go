package daemon

import "github.com/noironetworks/cilium-net/common/types"

type Daemon struct {
}

func NewDaemon() *Daemon {
	return &Daemon{}
}

func (d Daemon) Ping() (string, error) {
	return "Pong", nil
}

func (d Daemon) EndpointJoin(ep types.Endpoint) error {
	return nil
}

func (d Daemon) EndpointLeave(ep types.Endpoint) error {
	return nil
}
