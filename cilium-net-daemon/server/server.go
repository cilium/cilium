package server

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path"

	"github.com/noironetworks/cilium-net/common"
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
		return nil, fmt.Errorf("failed to create '%s' directory: %s", socketDir, err)
	}

	if err := os.Remove(socketPath); !os.IsNotExist(err) && err != nil {
		return nil, fmt.Errorf("failed to remove older listener socket: %s", err)
	}

	router := NewRouter(daemon)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create listen socket: %s", err)
	}
	if os.Getuid() == 0 {
		gid, err := common.GetGroupIDByName(common.CiliumGroupName)
		if err != nil {
			return nil, fmt.Errorf("failed while searching %s's group ID: %s", common.CiliumGroupName, err)
		}
		if err := os.Chown(socketPath, 0, gid); err != nil {
			return nil, fmt.Errorf("failed while setting up %s's group ID in %q: %s", common.CiliumGroupName, socketPath, err)
		}
		if err := os.Chmod(socketPath, 0660); err != nil {
			return nil, fmt.Errorf("failed while setting up %s's file permissions in %q: %s", common.CiliumGroupName, socketPath, err)
		}
	}

	return &Server{listener, router, socketPath}, nil
}

// Start starts the server and blocks to server HTTP requests.
func (d *Server) Start() error {
	log.Infof("Listening on %q", d.socketPath)
	return http.Serve(d.listener, d.router)
}

// Stop stops the HTTP listener.
func (d *Server) Stop() error {
	return d.listener.Close()
}
