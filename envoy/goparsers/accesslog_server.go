// Copyright 2017, 2018 Authors of Cilium
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

package main

import (
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/cilium/pkg/envoy/cilium"

	"github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"
)

type accessLogServer struct {
	tmpdir string
	path   string
	logs   chan cilium.LogEntry
}

// StartAccessLogServer starts the access log server.
func (s *accessLogServer) close() {
	os.RemoveAll(s.tmpdir)
}

// StartAccessLogServer starts the access log server.
func startAccessLogServer(t *testing.T, accessLogName string) *accessLogServer {
	tmpdir, err := ioutil.TempDir("", "cilium_envoy_go_test")
	if err != nil {
		t.Fatal("Failed to create a temporaty directory for testing")
	}
	accessLogPath := filepath.Join(tmpdir, accessLogName)

	// Create the access log listener
	os.Remove(accessLogPath) // Remove/Unlink the old unix domain socket, if any.
	accessLogListener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: accessLogPath, Net: "unixpacket"})
	if err != nil {
		t.Fatalf("Failed to open access log listen socket at %s: %v", accessLogPath, err)
	}
	accessLogListener.SetUnlinkOnClose(true)

	// Make the socket accessible by non-root Envoy proxies, e.g. running in
	// sidecar containers.
	if err = os.Chmod(accessLogPath, 0777); err != nil {
		t.Fatalf("Failed to change mode of access log listen socket at %s: %v", accessLogPath, err)
	}

	server := &accessLogServer{
		tmpdir: tmpdir,
		path:   accessLogPath,
		logs:   make(chan cilium.LogEntry, 2),
	}

	log.Info("Envoy: Starting Access Log Server")
	go func() {
		for {
			// Each Envoy listener opens a new connection over the Unix domain socket.
			// Multiple worker threads serving the listener share that same connection
			uc, err := accessLogListener.AcceptUnix()
			if err != nil {
				// These errors are expected when we are closing down
				if strings.Contains(err.Error(), "closed network connection") ||
					strings.Contains(err.Error(), "invalid argument") {
					break
				}
				log.WithError(err).Warn("Envoy: Failed to accept access log connection")
				continue
			}
			log.Info("Envoy: Accepted access log connection")

			// Serve this access log socket in a goroutine, so we can serve multiple
			// connections concurrently.
			go server.accessLogger(uc)
		}
	}()

	return server
}

// isEOF returns true if the error message ends in "EOF". ReadMsgUnix returns extra info in the beginning.
func isEOF(err error) bool {
	strerr := err.Error()
	errlen := len(strerr)
	return errlen >= 3 && strerr[errlen-3:] == io.EOF.Error()
}

func (s *accessLogServer) accessLogger(conn *net.UnixConn) {
	defer func() {
		log.Info("Envoy: Closing access log connection")
		conn.Close()
	}()

	buf := make([]byte, 4096)
	for {
		n, _, flags, _, err := conn.ReadMsgUnix(buf, nil)
		if err != nil {
			if !isEOF(err) {
				log.WithError(err).Error("Envoy: Error while reading from access log connection")
			}
			break
		}
		if flags&syscall.MSG_TRUNC != 0 {
			log.Warning("Envoy: Discarded truncated access log message")
			continue
		}
		pblog := cilium.LogEntry{}
		err = proto.Unmarshal(buf[:n], &pblog)
		if err != nil {
			log.WithError(err).Warning("Envoy: Discarded invalid access log message")
			continue
		}

		log.Infof("Envoy: Access log message: %s", pblog.String())
		s.logs <- pblog
	}
}
