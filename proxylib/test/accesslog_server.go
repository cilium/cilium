// Copyright 2017-2018 Authors of Cilium
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

package test

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/proxy/go/cilium/api"

	"github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type AccessLogServer struct {
	Path     string
	Logs     chan cilium.LogEntry
	closing  uint32 // non-zero if closing, accessed atomically
	listener *net.UnixListener
	conns    []*net.UnixConn
}

// Close removes the unix domain socket from the filesystem
func (s *AccessLogServer) Close() {
	if s != nil {
		atomic.StoreUint32(&s.closing, 1)
		s.listener.Close()
		for _, conn := range s.conns {
			conn.Close()
		}
		os.Remove(s.Path)
	}
}

// Clear empties the access log server buffer, counting the passes and drops
func (s *AccessLogServer) Clear() (passed, drops int) {
	passes, drops := 0, 0
	empty := false
	for !empty {
		select {
		case pblog := <-s.Logs:
			if pblog.EntryType == cilium.EntryType_Denied {
				drops++
			} else {
				passes++
			}
		case <-time.After(10 * time.Millisecond):
			empty = true
		}
	}
	return passes, drops
}

// StartAccessLogServer starts the access log server.
func StartAccessLogServer(accessLogName string, bufSize int) *AccessLogServer {
	accessLogPath := filepath.Join(Tmpdir, accessLogName)

	server := &AccessLogServer{
		Path: accessLogPath,
		Logs: make(chan cilium.LogEntry, bufSize),
	}

	// Create the access log listener
	os.Remove(accessLogPath) // Remove/Unlink the old unix domain socket, if any.
	var err error
	server.listener, err = net.ListenUnix("unixpacket", &net.UnixAddr{Name: accessLogPath, Net: "unixpacket"})
	if err != nil {
		log.Fatalf("Failed to open access log listen socket at %s: %v", accessLogPath, err)
	}
	server.listener.SetUnlinkOnClose(true)

	// Make the socket accessible by non-root Envoy proxies, e.g. running in
	// sidecar containers.
	if err = os.Chmod(accessLogPath, 0777); err != nil {
		log.Fatalf("Failed to change mode of access log listen socket at %s: %v", accessLogPath, err)
	}

	log.Debug("Starting Access Log Server")
	go func() {
		for {
			// Each Envoy listener opens a new connection over the Unix domain socket.
			// Multiple worker threads serving the listener share that same connection
			uc, err := server.listener.AcceptUnix()
			if err != nil {
				// These errors are expected when we are closing down
				if atomic.LoadUint32(&server.closing) != 0 ||
					strings.Contains(err.Error(), "closed network connection") ||
					strings.Contains(err.Error(), "invalid argument") {
					break
				}
				log.WithError(err).Warn("Failed to accept access log connection")
				continue
			}
			log.Debug("Accepted access log connection")

			server.conns = append(server.conns, uc)
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

func (s *AccessLogServer) accessLogger(conn *net.UnixConn) {
	defer func() {
		log.Debug("Closing access log connection")
		conn.Close()
	}()

	buf := make([]byte, 4096)
	for {
		n, _, flags, _, err := conn.ReadMsgUnix(buf, nil)
		if err != nil {
			if !isEOF(err) && atomic.LoadUint32(&s.closing) == 0 {
				log.WithError(err).Error("Error while reading from access log connection")
			}
			break
		}
		if flags&unix.MSG_TRUNC != 0 {
			log.Warning("Discarded truncated access log message")
			continue
		}
		pblog := cilium.LogEntry{}
		err = proto.Unmarshal(buf[:n], &pblog)
		if err != nil {
			log.WithError(err).Warning("Discarded invalid access log message")
			continue
		}

		log.Debugf("Access log message: %s", pblog.String())
		s.Logs <- pblog
	}
}
