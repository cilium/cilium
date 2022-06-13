package services

import (
	"flag"
	"os"
	"testing"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"
)

// Flags
var (
	flagUpdate = flag.Bool("update", false, "Update golden test files")
	flagDebug  = flag.Bool("debug", false, "Enable debug logging")
)

func TestMain(m *testing.M) {
	flag.Parse()
	if *flagDebug {
		logging.SetLogLevelToDebug()
	}
	logging.InitializeDefaultLogger()
	os.Exit(m.Run())
}

func TestGracefulTermination(t *testing.T) {
	option.Config.EnableK8sTerminatingEndpoint = true
	RunGoldenTest(t, "graceful-termination", *flagUpdate)
}
