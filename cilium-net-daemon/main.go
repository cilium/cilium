package main

import (
	"flag"
	"os"
	"time"

	d "github.com/noironetworks/cilium-net/cilium-net-daemon/daemon"
	common "github.com/noironetworks/cilium-net/common"

	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/op/go-logging"
)

const (
	logsDateFormat    = `-2006-01-02`
	logNameTimeFormat = time.RFC3339
)

var (
	socketPath   string
	logLevel     string
	log          = logging.MustGetLogger("cilium-net")
	stdoutFormat = logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
	)
	fileFormat = logging.MustStringFormatter(
		`%{time:` + time.RFC3339Nano + `} ` + os.Getenv("HOSTNAME") + ` %{shortfunc} ▶ %{level:.4s} %{id:03x} %{message}`,
	)
)

func setupLOG() {
	level, err := logging.LogLevel(logLevel)
	if err != nil {
		log.Fatal(err)
	}

	logTimename := time.Now().Format(logNameTimeFormat)
	ciliumLogsDir := os.TempDir() + string(os.PathSeparator) + "cilium-logs"
	if err := os.MkdirAll(ciliumLogsDir, 0755); err != nil {
		log.Error("Error while creating directory: %v", err)
	}

	fo, err := os.Create(ciliumLogsDir + string(os.PathSeparator) + "cilium-net-log-" + logTimename + ".log")
	if err != nil {
		log.Error("Error while creating log file: %v", err)
	}

	fileBackend := logging.NewLogBackend(fo, "", 0)

	fBF := logging.NewBackendFormatter(fileBackend, fileFormat)

	backend := logging.NewLogBackend(os.Stderr, "", 0)
	oBF := logging.NewBackendFormatter(backend, fileFormat)

	backendLeveled := logging.SetBackend(fBF, oBF)
	backendLeveled.SetLevel(level, "")
	log.SetBackend(backendLeveled)
}

func init() {
	flag.StringVar(&logLevel, "l", "info", "Set log level, valid options are (debug|info|warning|error|fatal|panic)")
	flag.StringVar(&socketPath, "s", common.CiliumSock, "Sets the socket path to listen for connections")
	flag.Parse()

	setupLOG()
}

func main() {
	daemon, err := d.NewDaemon(socketPath)
	if err != nil {
		log.Fatalf("Error while creating daemon: %s", err)
	}
	defer daemon.Stop()
	daemon.Start()
}
