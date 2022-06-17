package graceful_termination

import (
	"testing"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/test/control-plane/services"
)

func TestMain(m *testing.M) {
	services.TestMain(m)
}

func TestGracefulTermination(t *testing.T) {
	modConfig := func(c *option.DaemonConfig) {
		c.EnableK8sTerminatingEndpoint = true
	}
	services.
		NewGoldenTest(t, "graceful-termination").
		Run(t, modConfig)
}
