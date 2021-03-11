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
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "envoy-manager")

var (
	// RequiredEnvoyVersionSHA is set during build
	// Running Envoy version will be checked against `RequiredEnvoyVersionSHA`.
	// By default cilium-agent will fail to start if there is a version mismatch.
	RequiredEnvoyVersionSHA string

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

const (
	adminSock   = "envoy-admin.sock"
	ciliumEnvoy = "cilium-envoy"
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
	unixPath string
	level    string
}

func (a *admin) transact(query string) error {
	// Use a custom dialer to use a Unix domain socket for a HTTP connection.
	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(_, _ string) (net.Conn, error) { return net.Dial("unix", a.unixPath) },
		},
	}

	resp, err := client.Post(a.adminURL+query, "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	ret := strings.Replace(string(body), "\r", "", -1)
	log.Debugf("Envoy: Admin response to %s: %s", query, ret)
	return nil
}

func (a *admin) changeLogLevel(level logrus.Level) error {
	envoyLevel := mapLogLevel(level)

	if envoyLevel == a.level {
		log.Debugf("Envoy: Log level is already set as: %v", envoyLevel)
		return nil
	}

	err := a.transact("logging?level=" + envoyLevel)
	if err != nil {
		log.WithError(err).Warnf("Envoy: Failed to set log level to: %v", envoyLevel)
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
	stopCh chan struct{}
	errCh  chan error
	admin  *admin
}

// GetEnvoyVersion returns the envoy binary version string
func GetEnvoyVersion() string {
	out, err := exec.Command(ciliumEnvoy, "--version").Output()
	if err != nil {
		log.WithError(err).Fatalf("Envoy: Binary %q cannot be executed", ciliumEnvoy)
	}
	return strings.TrimSpace(string(out))
}

// StartEnvoy starts an Envoy proxy instance.
func StartEnvoy(stateDir, logPath string, baseID uint64) *Envoy {
	bootstrapPath := filepath.Join(stateDir, "bootstrap.pb")
	xdsPath := getXDSPath(stateDir)

	// Have to use a fake IP address:port even when we Dial to a Unix domain socket.
	// The address:port will be visible to Envoy as ':authority', but its value is
	// not meaningful.
	// Not using the normal localhost address to make it obvious that we are not
	// connecting to Envoy's admin interface via the IP stack.
	adminAddress := "192.0.2.34:56"
	adminPath := filepath.Join(stateDir, adminSock)

	e := &Envoy{
		stopCh: make(chan struct{}),
		errCh:  make(chan error, 1),
		admin: &admin{
			adminURL: "http://" + adminAddress + "/",
			unixPath: adminPath,
		},
	}

	// Use the same structure as Istio's pilot-agent for the node ID:
	// nodeType~ipAddress~proxyId~domain
	nodeId := "host~127.0.0.1~no-id~localdomain"

	// Create static configuration
	createBootstrap(bootstrapPath, nodeId, ingressClusterName,
		xdsPath, egressClusterName, ingressClusterName, adminPath)

	log.Debugf("Envoy: Starting: %v", *e)

	// make it a buffered channel so we can not only
	// read the written value but also skip it in
	// case no one reader reads it.
	started := make(chan bool, 1)
	go func() {
		var logWriter io.WriteCloser
		var logFormat string
		if logPath != "" {
			// Use the Envoy default log format when logging to a separate file
			logFormat = "[%Y-%m-%d %T.%e][%t][%l][%n] %v"
			logger := &lumberjack.Logger{
				Filename:   logPath,
				MaxSize:    100, // megabytes
				MaxBackups: 3,
				MaxAge:     28,   //days
				Compress:   true, // disabled by default
			}
			logWriter = logger
		} else {
			// Use log format that looks like Cilium logs when integrating logs
			// The logs will be reported as coming from the cilium-agent, so
			// we add the thread id to be able to differentiate between Envoy's
			// main and worker threads.
			logFormat = "%t|%l|%n|%v"

			// Create a piper that parses and writes into logrus the log
			// messages from Envoy.
			logWriter = newEnvoyLogPiper()
		}
		defer logWriter.Close()

		for {
			logLevel := logging.GetLevel(logging.DefaultLogger)
			cmd := exec.Command(ciliumEnvoy, "-l", mapLogLevel(logLevel), "-c", bootstrapPath, "--base-id", strconv.FormatUint(baseID, 10), "--log-format", logFormat)
			cmd.Stderr = logWriter
			cmd.Stdout = logWriter

			if err := cmd.Start(); err != nil {
				log.WithError(err).Warn("Envoy: Failed to start proxy")
				select {
				case started <- false:
				default:
				}
				return
			}
			log.Debugf("Envoy: Started proxy")
			select {
			case started <- true:
			default:
			}

			log.Infof("Envoy: Proxy started with pid %d", cmd.Process.Pid)
			metrics.SubprocessStart.WithLabelValues(ciliumEnvoy).Inc()

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
					log.WithError(err).Warn("Envoy: Proxy crashed")
				}
				close(crashCh)
			}()

			// start again after a short wait. If Cilium exits this should be enough
			// time to not start Envoy again in that case.
			log.Info("Envoy: Sleeping for 100ms before restarting proxy")
			time.Sleep(100 * time.Millisecond)

			select {
			case <-crashCh:
				// Start Envoy again
				continue
			case <-e.stopCh:
				log.Infof("Envoy: Stopping proxy with pid %d", cmd.Process.Pid)
				if err := e.admin.quit(); err != nil {
					log.WithError(err).Fatalf("Envoy: Envoy admin quit failed, killing process with pid %d", cmd.Process.Pid)

					if err := cmd.Process.Kill(); err != nil {
						log.WithError(err).Fatal("Envoy: Stopping Envoy failed")
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

// newEnvoyLogPiper creates a writer that parses and logs log messages written by Envoy.
func newEnvoyLogPiper() io.WriteCloser {
	reader, writer := io.Pipe()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(nil, 1024*1024)
	go func() {
		scopedLog := log.WithFields(logrus.Fields{
			logfields.LogSubsys: "unknown",
			logfields.ThreadID:  "unknown",
		})
		level := "debug"

		for scanner.Scan() {
			line := scanner.Text()
			var msg string

			parts := strings.SplitN(line, "|", 4)
			// Parse the line as a log message written by Envoy, assuming it
			// uses the configured format: "%t|%l|%n|%v".
			if len(parts) == 4 {
				threadID := parts[0]
				level = parts[1]
				loggerName := parts[2]
				// TODO: Parse msg to extract the source filename, line number, etc.
				msg = fmt.Sprintf("[%s", parts[3])

				scopedLog = log.WithFields(logrus.Fields{
					logfields.LogSubsys: fmt.Sprintf("envoy-%s", loggerName),
					logfields.ThreadID:  threadID,
				})
			} else {
				// If this line can't be parsed, it continues a multi-line log
				// message. In this case, log it at the same level and with the
				// same fields as the previous line.
				msg = line
			}

			if len(msg) == 0 {
				continue
			}

			// Map the Envoy log level to a logrus level.
			switch level {
			case "off", "critical", "error":
				scopedLog.Error(msg)
			case "warning":
				// Silently drop expected warnings if flowdebug is not enabled
				// TODO: Remove this special case when https://github.com/envoyproxy/envoy/issues/13504 is fixed.
				if !flowdebug.Enabled() && strings.Contains(msg, "Unable to use runtime singleton for feature envoy.http.headermap.lazy_map_min_size") {
					continue
				}
				scopedLog.Warn(msg)
			case "info":
				scopedLog.Info(msg)
			case "debug", "trace":
				scopedLog.Debug(msg)
			default:
				scopedLog.Debug(msg)
			}
		}
		if err := scanner.Err(); err != nil {
			log.WithError(err).Error("Error while parsing Envoy logs")
		}
		reader.Close()
	}()
	return writer
}

// isEOF returns true if the error message ends in "EOF". ReadMsgUnix returns extra info in the beginning.
func isEOF(err error) bool {
	strerr := err.Error()
	errlen := len(strerr)
	return errlen >= 3 && strerr[errlen-3:] == io.EOF.Error()
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

// ChangeLogLevel changes Envoy log level to correspond to the logrus log level 'level'.
func (e *Envoy) ChangeLogLevel(level logrus.Level) {
	e.admin.changeLogLevel(level)
}
