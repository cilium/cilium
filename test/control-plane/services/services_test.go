package services

import (
	"testing"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	//logging.SetLogLevelToDebug()
	logging.InitializeDefaultLogger()
}

func TestGracefulTermination(t *testing.T) {
	option.Config.EnableK8sTerminatingEndpoint = true
	RunGoldenTest(t, "graceful-termination")
}
