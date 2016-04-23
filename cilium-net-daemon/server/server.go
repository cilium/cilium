package server

import (
	"net"
	"net/http"
	"os"
	"path"

	"github.com/noironetworks/cilium-net/common/backend"

	"github.com/op/go-logging"
)

var (
	log = logging.MustGetLogger("cilium-net")
)

// Server listens for HTTP requests and sends them to our router.
type Server struct {
	listener   net.Listener
	router     Router
	socketPath string
}

// NewServer returns a new Server that listens for requests in socketPath and sends them
// to daemon.
func NewServer(socketPath string, daemon backend.CiliumBackend) (*Server, error) {
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

// Start starts the server and blocks to server HTTP requests.
func (d *Server) Start() error {
	log.Infof("Listening on \"%s\"", d.socketPath)
	return http.Serve(d.listener, d.router)
}

// Stop stops the HTTP listener.
func (d *Server) Stop() error {
	return d.listener.Close()
}
