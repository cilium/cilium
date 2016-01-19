package server

import (
	"net"
	"net/http"
	"os"
	"path"

	"github.com/noironetworks/cilium-net/cilium-net-daemon/daemon"

	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/op/go-logging"
)

var (
	log = logging.MustGetLogger("cilium-net")
)

type Server struct {
	listener   net.Listener
	router     Router
	socketPath string
}

func NewServer(socketPath string, daemon *daemon.Daemon) (*Server, error) {
	socketDir := path.Dir(socketPath)
	if err := os.MkdirAll(socketDir, 0700); err != nil {
		log.Fatalf("Error while creating '%s' directory: %+v", socketDir, err)
	}

	if err := os.Remove(socketPath); !os.IsNotExist(err) && err != nil {
		log.Fatalf("Error while trying to listen: %+v", err)
	}

	router := NewRouter(daemon)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("Error while trying to listen: %+v", err)
	}
	return &Server{listener, router, socketPath}, nil
}

func (d *Server) Start() error {
	log.Infof("Listening on \"%s\"", d.socketPath)
	return http.Serve(d.listener, d.router)
}

func (d *Server) Stop() error {
	return d.listener.Close()
}
