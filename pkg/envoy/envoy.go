// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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

	"github.com/cilium/lumberjack/v2"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/safeio"
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

type EnvoyAdminClient struct {
	adminURL string
	unixPath string
	level    string
}

func (a *EnvoyAdminClient) transact(query string) error {
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
	body, err := safeio.ReadAllLimit(resp.Body, safeio.MB)
	if err != nil {
		return err
	}
	ret := strings.Replace(string(body), "\r", "", -1)
	log.Debugf("Envoy: Admin response to %s: %s", query, ret)
	return nil
}

// ChangeLogLevel changes Envoy log level to correspond to the logrus log level 'level'.
func (a *EnvoyAdminClient) ChangeLogLevel(level logrus.Level) error {
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

func (a *EnvoyAdminClient) quit() error {
	return a.transact("quitquitquit")
}

// Envoy manages a running Envoy proxy instance via the
// ListenerDiscoveryService and RouteDiscoveryService gRPC APIs.
type EmbeddedEnvoy struct {
	stopCh chan struct{}
	errCh  chan error
	admin  *EnvoyAdminClient
}

// GetEnvoyVersion returns the envoy binary version string
func GetEnvoyVersion() string {
	out, err := exec.Command(ciliumEnvoy, "--version").Output()
	if err != nil {
		log.WithError(err).Fatalf("Envoy: Binary %q cannot be executed", ciliumEnvoy)
	}
	return strings.TrimSpace(string(out))
}

// StartEmbeddedEnvoy starts an Envoy proxy instance.
func StartEmbeddedEnvoy(runDir, logPath string, baseID uint64) *EmbeddedEnvoy {
	e := &EmbeddedEnvoy{
		stopCh: make(chan struct{}),
		errCh:  make(chan error, 1),
		admin:  NewEnvoyAdminClient(GetSocketDir(runDir)),
	}

	// Use the same structure as Istio's pilot-agent for the node ID:
	// nodeType~ipAddress~proxyId~domain
	nodeId := "host~127.0.0.1~no-id~localdomain"
	bootstrapPath := filepath.Join(runDir, "bootstrap.pb")
	xdsSocketPath := getXDSSocketPath(GetSocketDir(runDir))

	// Create static configuration
	createBootstrap(bootstrapPath, nodeId, ingressClusterName,
		xdsSocketPath, egressClusterName, ingressClusterName, getAdminSocketPath(GetSocketDir(runDir)))

	log.Debugf("Envoy: Starting: %v", *e)

	// make it a buffered channel, so we can not only
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
					// Avoid busy loop & hogging CPU resources by waiting before restarting envoy.
					time.Sleep(100 * time.Millisecond)
				}
				close(crashCh)
			}()

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

func NewEnvoyAdminClient(envoySocketDir string) *EnvoyAdminClient {
	// Have to use a fake IP address:port even when we Dial to a Unix domain socket.
	// The address:port will be visible to Envoy as ':authority', but its value is
	// not meaningful.
	// Not using the normal localhost address to make it obvious that we are not
	// connecting to Envoy's admin interface via the IP stack.
	adminAddress := "192.0.2.34:56"
	adminSocketPath := getAdminSocketPath(envoySocketDir)

	envoyAdmin := &EnvoyAdminClient{
		adminURL: fmt.Sprintf("http://%s/", adminAddress),
		unixPath: adminSocketPath,
	}

	return envoyAdmin
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

// Stop kills the Envoy process started with StartEmbeddedEnvoy. The gRPC API streams are terminated
// first.
func (e *EmbeddedEnvoy) Stop() error {
	close(e.stopCh)
	err, ok := <-e.errCh
	if ok {
		return err
	}
	return nil
}

func (e *EmbeddedEnvoy) GetAdminClient() *EnvoyAdminClient {
	return e.admin
}
