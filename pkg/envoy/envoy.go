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
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/policy"

	"github.com/golang/protobuf/proto"
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var log = logging.DefaultLogger

var (
	// envoyLevelMap maps logrus.Level values to Envoy (spdlog) log levels.
	envoyLevelMap = map[logrus.Level]string{
		logrus.PanicLevel: "off",
		logrus.FatalLevel: "critical",
		logrus.ErrorLevel: "error",
		logrus.WarnLevel:  "warning",
		logrus.InfoLevel:  "info",
		logrus.DebugLevel: "debug",
		// spdlog "trace" not mapped
	}

	tracing = false
)

// EnableTracing changes Envoy log level to "trace", producing the most logs.
func EnableTracing() {
	tracing = true
}

func mapLogLevel(level logrus.Level) string {
	if tracing {
		return "trace"
	}

	// Suppress the debug level if not debugging at flow level.
	if level == logrus.DebugLevel && !flowdebug.Enabled() {
		level = logrus.InfoLevel
	}
	return envoyLevelMap[level]
}

type admin struct {
	adminURL string
	level    string
}

func (a *admin) transact(query string) error {
	resp, err := http.Get(a.adminURL + query)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	ret := strings.Replace(string(body), "\r", "", -1)
	log.Debug("Envoy admin response to " + query + ": " + ret)
	return nil
}

func (a *admin) changeLogLevel(level logrus.Level) error {
	envoyLevel := mapLogLevel(level)

	if envoyLevel == a.level {
		log.Debug("Envoy log level is already set as: " + envoyLevel)
		return nil
	}

	err := a.transact("logging?level=" + envoyLevel)
	if err != nil {
		log.WithError(err).Warn("Envoy: Failed setting log level: ", envoyLevel)
	} else {
		a.level = envoyLevel
	}
	return err
}

func (a *admin) quit() error {
	return a.transact("quitquitquit")
}

// Envoy manages a running Envoy proxy instance via the
// ListenerDiscoveryService and RouteDiscoveryService gRPC APIs.
type Envoy struct {
	stopCh            chan struct{}
	errCh             chan error
	LogPath           string
	AccessLogPath     string
	accessLogListener *net.UnixListener
	xdsSock           string
	xds               *XDSServer
	admin             *admin
}

// Logger is used to feed access log entires from Envoy to cilium access log.
type Logger interface {
	Log(entry *HttpLogEntry)
}

// GetEnvoyVersion returns the envoy binary version string
func GetEnvoyVersion() string {
	out, err := exec.Command("cilium-envoy", "--version").Output()
	if err != nil {
		log.WithError(err).Fatal(`Envoy binary "cilium-envoy" cannot be executed`)
	}
	return strings.TrimSpace(string(out))
}

// StartEnvoy starts an Envoy proxy instance.
func StartEnvoy(adminPort uint32, stateDir, logPath string, baseID uint64) *Envoy {
	bootstrapPath := filepath.Join(stateDir, "bootstrap.pb")
	adminAddress := "127.0.0.1:" + strconv.FormatUint(uint64(adminPort), 10)
	xdsPath := filepath.Join(stateDir, "xds.sock")
	accessLogPath := filepath.Join(stateDir, "access_log.sock")

	e := &Envoy{
		stopCh:        make(chan struct{}),
		errCh:         make(chan error, 1),
		LogPath:       logPath,
		AccessLogPath: accessLogPath,
		xdsSock:       xdsPath,
		admin:         &admin{adminURL: "http://" + adminAddress + "/"},
	}

	// Use the same structure as Istio's pilot-agent for the node ID:
	// nodeType~ipAddress~proxyId~domain
	nodeId := "host~127.0.0.1~no-id~localdomain"

	// Create static configuration
	createBootstrap(bootstrapPath, nodeId, "cluster1", "version1",
		xdsPath, "cluster1", adminPort)

	e.startAccesslogServer(accessLogPath)

	log.Debug("Envoy: Starting ", *e)

	e.xds = createXDSServer(xdsPath, accessLogPath)

	// make it a buffered channel so we can not only
	// read the written value but also skip it in
	// case no one reader reads it.
	started := make(chan bool, 1)
	go func() {
		logger := &lumberjack.Logger{
			Filename:   logPath,
			MaxSize:    100, // megabytes
			MaxBackups: 3,
			MaxAge:     28,   //days
			Compress:   true, // disabled by default
		}
		defer logger.Close()
		var err error
		for {
			cmd := exec.Command("cilium-envoy", "-l", mapLogLevel(log.Level), "-c", bootstrapPath, "--base-id", strconv.FormatUint(baseID, 10))
			cmd.Stderr = logger
			cmd.Stdout = logger

			if err := cmd.Start(); err != nil {
				log.WithError(err).Warn("Envoy: failed to start.")
				select {
				case started <- false:
				default:
				}
				return
			}
			log.Debugf("Envoy: Started.")
			select {
			case started <- true:
			default:
			}

			log.Info("Envoy: Process started at pid ", cmd.Process.Pid)

			// We do not return after a successful start, but watch the Envoy process
			// and restart it if it crashes.
			// Waiting for the process execution is done in the goroutime.
			// The purpose of the "crash channel" is to inform the loop about their
			// Envoy process crash - after closing that channel by the goroutime,
			// the loop continues, the channel is recreated and the new process
			// is watched again.
			crashCh := make(chan struct{})
			go func() {
				if err := cmd.Wait(); err != nil {
					log.WithError(err).Warn("Envoy: Execution failed: ", err)
				}
				close(crashCh)
			}()

			// start again after a short wait. If Cilium exits this should be enough
			// time to not start Envoy again in that case.
			log.WithError(err).Info("Envoy: Sleeping for 100ms before respawning.")
			time.Sleep(100 * time.Millisecond)

			select {
			case <-crashCh:
				// Start Envoy again
				continue
			case <-e.stopCh:
				// Close the access log server
				if e.accessLogListener != nil {
					e.accessLogListener.Close()
					e.accessLogListener = nil
				}
				log.Info("Envoy: Stopping process ", cmd.Process.Pid)
				e.xds.stop()
				if err := e.admin.quit(); err != nil {
					log.WithError(err).Fatal("Envoy: Admin quit failed, killing process ", cmd.Process.Pid)

					if err := cmd.Process.Kill(); err != nil {
						log.WithError(err).Fatal("Envoy: Stopping failed")
						e.errCh <- err
					}
				}
				close(e.errCh)
				return
			}
		}
	}()

	if <-started {
		return e
	}

	return nil
}

// isEOF returns true if the error message ends in "EOF". ReadMsgUnix returns extra info in the beginning.
func isEOF(err error) bool {
	strerr := err.Error()
	errlen := len(strerr)
	return errlen >= 3 && strerr[errlen-3:] == io.EOF.Error()
}

func (e *Envoy) startAccesslogServer(accessLogPath string) {
	// Create the access log listener
	os.Remove(accessLogPath) // Remove/Unlink the old unix domain socket, if any.
	var err error
	e.accessLogListener, err = net.ListenUnix("unixpacket", &net.UnixAddr{Name: accessLogPath, Net: "unixpacket"})
	if err != nil {
		log.WithError(err).Fatal("Envoy: Failed to listen at ", accessLogPath)
	}
	e.accessLogListener.SetUnlinkOnClose(true)

	go func() {
		for {
			// Each Envoy listener opens a new connection over the Unix domain socket.
			// Multiple worker threads serving the listener share that same connection
			uc, err := e.accessLogListener.AcceptUnix()
			if err != nil {
				// These errors are expected when we are closing down
				if !strings.Contains(err.Error(), "closed network connection") &&
					!strings.Contains(err.Error(), "invalid argument") {
					log.WithError(err).Error("AcceptUnix failed")
				}
				break
			}
			log.Info("Envoy: Access log connection opened")
			e.accessLogger(uc)
		}
	}()
}

func (e *Envoy) accessLogger(conn *net.UnixConn) {
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
		logger := e.xds.findListenerLogger(pblog.CiliumResourceName)

		// Call the logger.
		if logger != nil {
			logger.Log(&pblog)
		} else {
			log.Infof("Envoy: Orphan Access log message for %s: %s", pblog.CiliumResourceName, pblog.String())
		}
	}
}

// StopEnvoy kills the Envoy process started with StartEnvoy. The gRPC API streams are terminated
// first.
func (e *Envoy) StopEnvoy() error {
	close(e.stopCh)
	err, ok := <-e.errCh
	if ok {
		return err
	}
	return nil
}

// AddListener adds a listener to a running Envoy proxy.
func (e *Envoy) AddListener(name string, endpoint_policy_name string, port uint16, l7rules policy.L7DataMap, isIngress bool, logger Logger, wg *completion.WaitGroup) {
	e.xds.addListener(name, endpoint_policy_name, port, l7rules, isIngress, logger, wg)
}

// UpdateListener changes to the L7 rules of an existing Envoy Listener.
func (e *Envoy) UpdateListener(name string, l7rules policy.L7DataMap, wg *completion.WaitGroup) {
	e.xds.updateListener(name, l7rules, wg)
}

// RemoveListener removes an existing Envoy Listener.
func (e *Envoy) RemoveListener(name string, wg *completion.WaitGroup) {
	e.xds.removeListener(name, wg)
}

// ChangeLogLevel changes Envoy log level to correspond to the logrus log level 'level'.
func (e *Envoy) ChangeLogLevel(level logrus.Level) {
	e.admin.changeLogLevel(level)
}
