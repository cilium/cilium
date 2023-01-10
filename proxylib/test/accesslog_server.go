// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/golang/protobuf/proto"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/lock"
)

type AccessLogServer struct {
	Path     string
	Logs     chan cilium.EntryType
	done     chan struct{}
	listener *net.UnixListener
	mu       lock.Mutex // protects conns
	conns    []*net.UnixConn
}

// Close removes the unix domain socket from the filesystem
func (s *AccessLogServer) Close() {
	if s != nil {
		close(s.done)
		s.listener.Close()
		s.mu.Lock()
		for _, conn := range s.conns {
			conn.Close()
		}
		s.mu.Unlock()
		os.Remove(s.Path)
	}
}

func (s *AccessLogServer) isClosing() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// Clear empties the access log server buffer, counting the passes and drops
func (s *AccessLogServer) Clear() (passed, drops int) {
	passes, drops := 0, 0
	empty := false
	for !empty {
		select {
		case entryType := <-s.Logs:
			if entryType == cilium.EntryType_Denied {
				drops++
			} else {
				passes++
			}
		case <-inctimer.After(10 * time.Millisecond):
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
		Logs: make(chan cilium.EntryType, bufSize),
		done: make(chan struct{}),
	}

	// Create the access log listener
	os.Remove(accessLogPath) // Remove/Unlink the old unix domain socket, if any.
	var err error
	server.listener, err = net.ListenUnix("unixpacket", &net.UnixAddr{Name: accessLogPath, Net: "unixpacket"})
	if err != nil {
		logrus.Fatalf("Failed to open access log listen socket at %s: %v", accessLogPath, err)
	}
	server.listener.SetUnlinkOnClose(true)

	// Make the socket accessible by non-root Envoy proxies, e.g. running in
	// sidecar containers.
	if err = os.Chmod(accessLogPath, 0777); err != nil {
		logrus.Fatalf("Failed to change mode of access log listen socket at %s: %v", accessLogPath, err)
	}

	logrus.Debug("Starting Access Log Server")
	go func() {
		for {
			// Each Envoy listener opens a new connection over the Unix domain socket.
			// Multiple worker threads serving the listener share that same connection
			uc, err := server.listener.AcceptUnix()
			if err != nil {
				// These errors are expected when we are closing down
				if server.isClosing() ||
					errors.Is(err, net.ErrClosed) ||
					errors.Is(err, syscall.EINVAL) {
					break
				}
				logrus.WithError(err).Warn("Failed to accept access log connection")
				continue
			}

			if server.isClosing() {
				break
			}

			logrus.Debug("Accepted access log connection")

			server.mu.Lock()
			server.conns = append(server.conns, uc)
			server.mu.Unlock()
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
		logrus.Debug("Closing access log connection")
		conn.Close()
	}()

	buf := make([]byte, 4096)
	for {
		n, _, flags, _, err := conn.ReadMsgUnix(buf, nil)
		if err != nil {
			if !isEOF(err) && !s.isClosing() {
				logrus.WithError(err).Error("Error while reading from access log connection")
			}
			break
		}
		if flags&unix.MSG_TRUNC != 0 {
			logrus.Warning("Discarded truncated access log message")
			continue
		}
		pblog := cilium.LogEntry{}
		err = proto.Unmarshal(buf[:n], &pblog)
		if err != nil {
			logrus.WithError(err).Warning("Discarded invalid access log message")
			continue
		}

		logrus.Debugf("Access log message: %s", pblog.String())
		s.Logs <- pblog.EntryType
	}
}
