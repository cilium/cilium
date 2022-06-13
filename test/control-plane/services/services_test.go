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

	option.Config.EnableHealthCheckNodePort = false

	os.Exit(m.Run())
}

func TestGracefulTermination(t *testing.T) {
	defer func(old bool) { option.Config.EnableK8sTerminatingEndpoint = old }(option.Config.EnableK8sTerminatingEndpoint)
	option.Config.EnableK8sTerminatingEndpoint = true
	RunGoldenTest(t, "graceful-termination", *flagUpdate)
}

func TestDualStack(t *testing.T) {
	defer func(old bool) { option.Config.EnableNodePort = old }(option.Config.EnableNodePort)
	defer func(old bool) { option.Config.EnableIPv6 = old }(option.Config.EnableIPv6)
	option.Config.EnableNodePort = true
	option.Config.EnableIPv6 = true
	RunGoldenTest(t, "dual-stack", *flagUpdate)
}
