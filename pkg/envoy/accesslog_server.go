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

package envoy

import (
	"github.com/golang/protobuf/proto"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func getAccessLogPath(stateDir string) string {
	return filepath.Join(stateDir, "access_log.sock")
}

// StartAccessLogServer starts the access log server.
func StartAccessLogServer(stateDir string, xdsServer *XDSServer) {
	accessLogPath := getAccessLogPath(stateDir)

	// Create the access log listener
	os.Remove(accessLogPath) // Remove/Unlink the old unix domain socket, if any.
	accessLogListener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: accessLogPath, Net: "unixpacket"})
	if err != nil {
		log.WithError(err).Fatal("Envoy: Failed to listen at ", accessLogPath)
	}
	accessLogListener.SetUnlinkOnClose(true)

	// Make the socket accessible by non-root Envoy proxies, e.g. running in
	// sidecar containers.
	if err = os.Chmod(accessLogPath, 0777); err != nil {
		log.WithError(err).Fatal("Envoy: can't change mode of access log socket at ", accessLogPath)
	}

	go func() {
		for {
			// Each Envoy listener opens a new connection over the Unix domain socket.
			// Multiple worker threads serving the listener share that same connection
			uc, err := accessLogListener.AcceptUnix()
			if err != nil {
				// These errors are expected when we are closing down
				if !strings.Contains(err.Error(), "closed network connection") &&
					!strings.Contains(err.Error(), "invalid argument") {
					log.WithError(err).Error("AcceptUnix failed")
				}
				break
			}
			log.Info("Envoy: Access log connection opened")
			accessLogger(uc, xdsServer)
		}
	}()
}

func accessLogger(conn *net.UnixConn, xdsServer *XDSServer) {
	defer func() {
		log.Info("Envoy: Access log closing")
		conn.Close()
	}()

	buf := make([]byte, 4096)
	for {
		n, _, flags, _, err := conn.ReadMsgUnix(buf, nil)
		if err != nil {
			if !isEOF(err) {
				log.WithError(err).Error("Envoy: Access log read error")
			}
			break
		}
		if flags&syscall.MSG_TRUNC != 0 {
			log.Warning("Envoy: Truncated access log message discarded.")
			continue
		}
		pblog := HttpLogEntry{}
		err = proto.Unmarshal(buf[:n], &pblog)
		if err != nil {
			log.WithError(err).Warning("Envoy: Invalid accesslog.proto HttpLogEntry message.")
			continue
		}

		// Correlate the log entry with a listener
		logger := xdsServer.findListenerLogger(pblog.CiliumResourceName)

		// Call the logger.
		if logger != nil {
			logger.Log(&pblog)
		} else {
			log.Infof("Envoy: Orphan Access log message for %s: %s", pblog.CiliumResourceName, pblog.String())
		}
	}
}
