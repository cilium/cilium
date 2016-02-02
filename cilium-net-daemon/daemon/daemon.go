package daemon

import (
	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/op/go-logging"
)

var (
	log = logging.MustGetLogger("cilium-net")
)

type Daemon struct {
	libDir string
}

func NewDaemon(libdir string) *Daemon {
	return &Daemon{
		libDir: libdir,
	}
}
