package services

import (
	"flag"
	"os"
	"testing"

	"github.com/cilium/cilium/pkg/logging"
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
