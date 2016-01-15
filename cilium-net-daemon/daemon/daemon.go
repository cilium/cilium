package cilium_net_daemon

import (
	"net"
	"net/http"
	"os"
	"path"

	"github.com/noironetworks/cilium-net/cilium-net-daemon/Godeps/_workspace/src/github.com/gorilla/mux"
	"github.com/noironetworks/cilium-net/cilium-net-daemon/Godeps/_workspace/src/github.com/op/go-logging"
)

var (
	log = logging.MustGetLogger("cilium-net")
)

type Daemon struct {
	listener   net.Listener
	router     *mux.Router
	socketPath string
}

func NewDaemon(socketPath string) (*Daemon, error) {
	socketDir := path.Dir(socketPath)
	if err := os.MkdirAll(socketDir, 0700); err != nil {
		log.Fatalf("Error while creating '%s' directory: %+v", socketDir, err)
	}

	if err := os.Remove(socketPath); !os.IsNotExist(err) && err != nil {
		log.Fatalf("Error while trying to listen: %+v", err)
	}

	router := NewRouter()
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("Error while trying to listen: %+v", err)
	}
	return &Daemon{listener, router, socketPath}, nil
}

func (d *Daemon) Start() error {
	log.Infof("Listening on \"%s\"", d.socketPath)
	return http.Serve(d.listener, d.router)
}

func (d *Daemon) Stop() error {
	return d.listener.Close()
}
