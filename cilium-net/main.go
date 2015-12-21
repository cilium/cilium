package main

import (
	"flag"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/op/go-logging"
)

const (
	defaultPath       = "/var/run/cilium"
	defaultSocketPath = defaultPath + "/cilium-net.sock"
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
	flag.StringVar(&socketPath, "s", defaultSocketPath, "Sets the socket path to listen for connections")
	flag.Parse()

	setupLOG()
}

func main() {
	if err := os.MkdirAll(defaultPath, 0700); err != nil {
		log.Fatalf("Error while creating '%s' directory: %+v", defaultPath, err)
	}

	if err := os.Remove(socketPath); !os.IsNotExist(err) && err != nil {
		log.Fatalf("Error while trying to listen: %+v", err)
	}
	router := NewRouter()
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("Error while trying to listen: %+v", err)
	}
	defer listener.Close()
	log.Infof("Listen on \"%s\"", socketPath)
	log.Fatal(http.Serve(listener, router))
}
