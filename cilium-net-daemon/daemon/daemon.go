package daemon

import (
	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/op/go-logging"

	"github.com/noironetworks/cilium-net/bpf/lxcmap"
)

var (
	log = logging.MustGetLogger("cilium-net")
)

type Daemon struct {
	libDir string
	lxcMap *lxcmap.LxcMap
}

func NewDaemon(libdir string, m *lxcmap.LxcMap) *Daemon {
	return &Daemon{
		libDir: libdir,
		lxcMap: m,
	}
}
