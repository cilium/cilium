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
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/policy"

	"github.com/golang/protobuf/proto"
	"github.com/sirupsen/logrus"
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
)

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
	envoyLevel := envoyLevelMap[level]
	if envoyLevel != a.level {
		err := a.transact("logging?level=" + envoyLevel)
		if err != nil {
			log.WithError(err).Warn("Envoy: Failed setting log level: ", envoyLevel)
		} else {
			a.level = envoyLevel
		}
		return err
	}
	log.Debug("Envoy log level is already set as: " + envoyLevel)
	return nil
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
	ldsSock           string
	lds               *LDSServer
	rdsSock           string
	rds               *RDSServer
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
func StartEnvoy(adminPort uint32, stateDir, logDir string, baseID uint64) *Envoy {
	bootstrapPath := filepath.Join(stateDir, "bootstrap.pb")
	logPath := filepath.Join(logDir, "cilium-envoy.log")
	adminAddress := "127.0.0.1:" + strconv.FormatUint(uint64(adminPort), 10)
	ldsPath := filepath.Join(stateDir, "lds.sock")
	rdsPath := filepath.Join(stateDir, "rds.sock")
	accessLogPath := filepath.Join(stateDir, "access_log.sock")

	e := &Envoy{
		stopCh:        make(chan struct{}),
		errCh:         make(chan error, 1),
		LogPath:       logPath,
		AccessLogPath: accessLogPath,
		ldsSock:       ldsPath,
		rdsSock:       rdsPath,
		admin:         &admin{adminURL: "http://" + adminAddress + "/"},
	}

	// Use the same structure as Istio's pilot-agent for the node ID:
	// nodeType~ipAddress~proxyId~domain
	nodeId := "host~127.0.0.1~no-id~localdomain"

	// Create static configuration
	createBootstrap(bootstrapPath, nodeId, "cluster1", "version1",
		"ldsCluster", ldsPath, "rdsCluster", rdsPath, "cluster1", adminPort)

	e.startAccesslogServer(accessLogPath)

	log.Debug("Envoy: Starting ", *e)

	e.lds = createLDSServer(ldsPath, accessLogPath)
	e.rds = createRDSServer(rdsPath, e.lds)
	e.rds.run()
	e.lds.run(e.rds)

	// make it a buffered channel so we can not only
	// read the written value but also skip it in
	// case no one reader reads it.
	started := make(chan bool, 1)
	go func() {
		var logFile *os.File
		var err error
		for {
			// Open log file
			// TODO: log rotation!
			if logFile == nil {
				logFile, err = os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					log.WithError(err).Warn("Envoy: Can not open log file ", logPath)
				}
			}

			name := "cilium-envoy"
			logLevel := envoyLevelMap[log.Level]
			if logLevel == "" {
				logLevel = envoyLevelMap[logrus.InfoLevel]
			}

			cmd := exec.Command(name, "-l", logLevel, "-c", bootstrapPath, "--base-id", strconv.FormatUint(baseID, 10))
			cmd.Stderr = logFile
			cmd.Stdout = logFile

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

			if logFile != nil {
				logFile.Close()
				logFile = nil
			}
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
				e.rds.stop()
				e.lds.stop()
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
		l := e.lds.findListener(pblog.CiliumResourceName)

		// Call the logger.
		if l != nil {
			l.logger.Log(&pblog)
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
func (e *Envoy) AddListener(name string, port uint16, l7rules policy.L7DataMap, isIngress bool, logger Logger, wg *completion.WaitGroup) {
	e.lds.addListener(name, port, l7rules, isIngress, logger, wg)
}

// UpdateListener changes to the L7 rules of an existing Envoy Listener.
func (e *Envoy) UpdateListener(name string, l7rules policy.L7DataMap, wg *completion.WaitGroup) {
	e.lds.updateListener(name, l7rules, wg)
}

// RemoveListener removes an existing Envoy Listener.
func (e *Envoy) RemoveListener(name string, wg *completion.WaitGroup) {
	e.lds.removeListener(name, wg)
}

// ChangeLogLevel changes Envoy log level to correspond to the logrus log level 'level'.
func (e *Envoy) ChangeLogLevel(level logrus.Level) {
	e.admin.changeLogLevel(level)
}
