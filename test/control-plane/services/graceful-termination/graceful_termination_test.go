package services

import (
	"flag"
	"os"
	"testing"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/test/control-plane/services"
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

	option.Config.Populate()
	option.Config.EnableHealthCheckNodePort = false

	os.Exit(m.Run())
}

func TestGracefulTermination(t *testing.T) {
	defer setOption(&option.Config.EnableK8sTerminatingEndpoint).restore()
	services.NewGoldenTest(t, "graceful-termination", *flagUpdate).Run(t)
}

//
// Utils for working with option.Config.
//

type oldOption struct {
	opt *bool
	old bool
}

func setOption(opt *bool) oldOption {
	old := oldOption{opt, *opt}
	*opt = true
	return old
}

func unsetOption(opt *bool) oldOption {
	old := oldOption{opt, *opt}
	*opt = false
	return old
}

func (o oldOption) restore() {
	*o.opt = o.old
}
