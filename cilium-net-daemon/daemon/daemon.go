package daemon

import (
	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/op/go-logging"
)

var (
	log = logging.MustGetLogger("cilium-net")
)

type Daemon struct {
}

func NewDaemon() *Daemon {
	return &Daemon{}
}
