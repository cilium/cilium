// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumTest

import (
	"fmt"
	"os"
	"testing"
	"time"

	gops "github.com/google/gops/agent"
	"github.com/onsi/ginkgo"
	ginkgoconfig "github.com/onsi/ginkgo/config"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/test/config"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/logger"

	// These packages are where Ginkgo test specs live. They are declared as blank
	// (_) global variables and are pulled in using package import side effects.
	_ "github.com/cilium/cilium/test/k8s"
	_ "github.com/cilium/cilium/test/runtime"
)

var (
	log             = logging.DefaultLogger
	DefaultSettings = map[string]string{
		"K8S_VERSION": "1.33",
	}
	commandsLogFileName = "cmds.log"
)

func init() {
	// Open socket for using gops to get stacktraces in case the tests deadlock.
	if err := gops.Listen(gops.Options{ShutdownCleanup: true}); err != nil {
		fmt.Fprintf(os.Stderr, "unable to start gops: %s", err)
		os.Exit(1)
	}

	for k, v := range DefaultSettings {
		getOrSetEnvVar(k, v)
	}
	os.RemoveAll(helpers.TestResultsPath)

	format.UseStringerRepresentation = true
}

func configLogsOutput() {
	log.SetLevel(logrus.DebugLevel)
	log.Out = &logger.TestLogWriter
	logrus.SetFormatter(&logger.Formatter)
	log.Formatter = &logger.Formatter
	log.Hooks.Add(&logger.LogHook{})

	GinkgoWriter = NewWriter(log.Out)
}

func showCommands() {
	if !config.CiliumTestConfig.ShowCommands {
		return
	}

	helpers.SSHMetaLogs = NewWriter(os.Stdout)
}

func Test(t *testing.T) {
	if config.CiliumTestConfig.TestScope != "" {
		helpers.UserDefinedScope = config.CiliumTestConfig.TestScope
		fmt.Printf("User specified the scope:  %q\n", config.CiliumTestConfig.TestScope)
	}

	// Skip the ginkgo test suite if 'go test ./...' is run on the repository.
	// Require passing a scope or focus to pull in the ginkgo suite.
	if _, err := helpers.GetScope(); err != nil {
		fmt.Println("No Ginkgo test scope defined, skipping test suite of package test/")
		t.Skip("Run this package through Ginkgo with the --focus or -cilium.testScope options")
	}

	if integration := helpers.GetCurrentIntegration(); integration != "" {
		fmt.Printf("Using CNI_INTEGRATION=%q\n", integration)

		switch integration {
		case helpers.CIIntegrationMicrok8s:
			fallthrough
		case helpers.CIIntegrationMinikube:
			fmt.Printf("Disabling multinode testing")
			config.CiliumTestConfig.Multinode = false
		default:
		}
	}

	configLogsOutput()
	showCommands()

	if config.CiliumTestConfig.HoldEnvironment {
		RegisterFailHandler(helpers.Fail)
	} else {
		RegisterFailHandler(Fail)
	}
	junitReporter := NewJUnitReporter(fmt.Sprintf(
		"%s.xml", helpers.GetScopeWithVersion()))
	RunSpecsWithDefaultAndCustomReporters(
		t, fmt.Sprintf("Suite-%s", helpers.GetScopeWithVersion()),
		[]ginkgo.Reporter{junitReporter})
}

func goReportSetupStatus() chan bool {
	if ginkgoconfig.DefaultReporterConfig.Verbose ||
		ginkgoconfig.DefaultReporterConfig.Succinct {
		// Dev told us they want more/less information than default. Skip.
		return nil
	}

	exit := make(chan bool)
	go func() {
		done := false
		iter := 0
		for {
			var out string
			select {
			case ok := <-exit:
				if ok {
					out = "●\n"
				} else {
					out = "◌\n"
				}
				done = true
			default:
				out = string(rune(int('◜') + iter%4))
			}
			fmt.Printf("\rSetting up test suite... %s", out)
			if done {
				return
			}
			time.Sleep(250 * time.Millisecond)
			iter++
		}
	}()
	return exit
}

func reportFailure(vm string, err error) {
	failmsg := fmt.Sprintf(`
        ===================== ERROR - VM PROVISION FAILED =====================

        Unable to provision Runtime test environment %q: %s", vm, err

        =======================================================================
        `, vm, err)
	GinkgoPrint(failmsg)
	Fail(failmsg)
}

var _ = BeforeAll(func() {
	helpers.Init()
	By("Starting tests: command line parameters: %+v environment variables: %v", config.CiliumTestConfig, os.Environ())
	go func() {
		defer GinkgoRecover()
		time.Sleep(config.CiliumTestConfig.Timeout)
		msg := fmt.Sprintf("Test suite timed out after %s", config.CiliumTestConfig.Timeout)
		By(msg)
		Fail(msg)
	}()

	var err error

	logger := log.WithFields(logrus.Fields{"testName": "BeforeAll"})
	scope, err := helpers.GetScope()
	if err != nil {
		Fail(fmt.Sprintf(
			"Cannot get the scope for running test, please use --cilium.testScope option: %s",
			err))
	}

	if config.CiliumTestConfig.SSHConfig != "" {
		// If we set a different VM that it's not in our test environment
		// ginkgo cannot provision it, so skip setup below.
		return
	}

	if progressChan := goReportSetupStatus(); progressChan != nil {
		defer func() { progressChan <- err == nil }()
	}

	switch scope {
	case helpers.Runtime:
		vm := helpers.InitRuntimeHelper(helpers.Runtime, logger)
		err = vm.SetUpCilium()

		if err != nil {
			// AfterFailed function is not defined in this scope, fired the
			// ReportFailed manually for this assert to gather cilium logs Fix
			// #3428
			vm.ReportFailed()
			log.WithError(err).Error("Cilium was unable to be set up correctly")
			reportFailure(helpers.Runtime, err)
		}
		go vm.PprofReport()

	case helpers.K8s:
		kubectl := helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		kubectl.PrepareCluster()

		// Cleanup all cilium components if there are any leftovers from previous
		// run, like when running tests locally.
		kubectl.CleanupCiliumComponents()

		kubectl.ApplyDefault(kubectl.GetFilePath("../examples/kubernetes/addons/prometheus/monitoring-example.yaml"))

		go kubectl.PprofReport()
	}
})

func getOrSetEnvVar(key, value string) {
	if val := os.Getenv(key); val == "" {
		log.Infof("environment variable %q was not set; setting to default value %q", key, value)
		os.Setenv(key, value)
	}
}

var _ = AfterEach(func() {

	// Send the Checks output to Junit report to be render on Jenkins.
	defer helpers.CheckLogs.Reset()
	GinkgoPrint("<Checks>\n%s\n</Checks>\n", helpers.CheckLogs.Buffer.String())

	defer logger.TestLogWriterReset()
	err := helpers.CreateLogFile(logger.TestLogFileName, logger.TestLogWriter.Bytes())
	if err != nil {
		log.WithError(err).Errorf("cannot create log file '%s'", logger.TestLogFileName)
		return
	}

	defer helpers.SSHMetaLogs.Reset()
	err = helpers.CreateLogFile(commandsLogFileName, helpers.SSHMetaLogs.Bytes())
	if err != nil {
		log.WithError(err).Errorf("cannot create log file '%s'", commandsLogFileName)
		return
	}
})
