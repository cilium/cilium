//
// Copyright 2016 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package server

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/daemon/daemon"

	"github.com/op/go-logging"
)

var (
	log = logging.MustGetLogger("cilium-net")
)

// Server listens for HTTP requests and sends them to our router.
type Server interface {
	Start() error
	Stop() error
}

type server struct {
	listener   net.Listener
	socketPath string
	router     Router
}

// NewServer returns a new Server that listens for requests in socketPath and sends them
// to daemon.
func NewServer(socketPath string, daemon *daemon.Daemon) (Server, error) {
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
		if err == nil {
			if err := os.Chown(socketPath, 0, gid); err != nil {
				return nil, fmt.Errorf("failed while setting up %s's group ID in %q: %s", common.CiliumGroupName, socketPath, err)
			}
		} else {
			log.Warningf("Group %s not found: %s", common.CiliumGroupName, err)
		}
		if err := os.Chmod(socketPath, 0660); err != nil {
			return nil, fmt.Errorf("failed while setting up %s's file permissions in %q: %s", common.CiliumGroupName, socketPath, err)
		}
	}

	return server{listener, socketPath, router}, nil
}

// Start starts the server and blocks to server HTTP requests.
func (d server) Start() error {
	log.Infof("Listening on %q", d.socketPath)
	return http.Serve(d.listener, d.router)
}

// Stop stops the HTTP listener.
func (d server) Stop() error {
	return d.listener.Close()
}
