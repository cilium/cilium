// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumTest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
		"K8S_VERSION": "1.26",
	}
	k8sNodesEnv         = "K8S_NODES"
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

func reportCreateVMFailure(vm string, err error) {
	failmsg := fmt.Sprintf(`
        ===================== ERROR - VM PROVISION FAILED =====================

        Unable to provision and start VM %q: %s", vm, err

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
		// Boot / provision VMs if specified by configuration.
		if config.CiliumTestConfig.Reprovision {
			err = helpers.CreateVM(helpers.Runtime)
			if err != nil {
				log.WithError(err).Error("Error starting VM")
				reportCreateVMFailure(helpers.Runtime, err)
			}
		}

		vm := helpers.InitRuntimeHelper(helpers.Runtime, logger)
		err = vm.SetUpCilium()

		if err != nil {
			// AfterFailed function is not defined in this scope, fired the
			// ReportFailed manually for this assert to gather cilium logs Fix
			// #3428
			vm.ReportFailed()
			log.WithError(err).Error("Cilium was unable to be set up correctly")
			reportCreateVMFailure(helpers.Runtime, err)
		}
		go vm.PprofReport()

	case helpers.K8s:
		// FIXME: This should be:
		// Start k8s1 and provision kubernetes.
		// When finish, start to build cilium in background
		// Start k8s2
		// Wait until compilation finished, and pull cilium image on k8s2

		// Name for K8s VMs depends on K8s version that is running.

		// Boot / provision VMs if specified by configuration.
		if config.CiliumTestConfig.Reprovision {
			var nodesInt int
			nodes := os.Getenv(k8sNodesEnv)
			if nodes != "" {
				nodesInt, err = strconv.Atoi(nodes)
				if err != nil {
					Fail(fmt.Sprintf("%s value is not a number %q", k8sNodesEnv, nodes))
				}
			}

			err = helpers.CreateVM(helpers.K8s1VMName())
			if err != nil {
				reportCreateVMFailure(helpers.K8s1VMName(), err)
			}

			if nodesInt != 1 {
				err = helpers.CreateVM(helpers.K8s2VMName())
				if err != nil {
					reportCreateVMFailure(helpers.K8s2VMName(), err)
				}
			}

			// For Nightly test we need to have more than two kubernetes nodes. If
			// the env variable K8S_NODES is present, more nodes will be created.
			if nodesInt > 2 {
				for i := 3; i <= nodesInt; i++ {
					vmName := fmt.Sprintf("%s%d-%s", helpers.K8s, i, helpers.GetCurrentK8SEnv())
					err = helpers.CreateVM(vmName)
					if err != nil {
						reportCreateVMFailure(vmName, err)
					}
				}
			}
		}
		kubectl := helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		kubectl.PrepareCluster()

		// Cleanup all cilium components if there are any leftovers from previous
		// run, like when running tests locally.
		kubectl.CleanupCiliumComponents()

		kubectl.ApplyDefault(kubectl.GetFilePath("../examples/kubernetes/addons/prometheus/monitoring-example.yaml"))

		go kubectl.PprofReport()
	}
})

var _ = AfterSuite(func() {
	if !helpers.IsRunningOnJenkins() {
		GinkgoPrint("AfterSuite: not running on Jenkins; leaving VMs running for debugging")
		return
	}
	// Errors are not checked here because it should fail on BeforeAll
	scope, _ := helpers.GetScope()
	GinkgoPrint("cleaning up VMs started for %s tests", scope)
	switch scope {
	case helpers.Runtime:
		helpers.DestroyVM(helpers.Runtime)
	case helpers.K8s:
		helpers.DestroyVM(helpers.K8s1VMName())
		helpers.DestroyVM(helpers.K8s2VMName())
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

	// This piece of code is to enable zip attachments on Junit Output.
	if TestFailed() && helpers.IsRunningOnJenkins() {
		// ReportDirectory is already created. No check the error
		path, _ := helpers.CreateReportDirectory()
		zipFileName := fmt.Sprintf("%s_%s.zip", helpers.MakeUID(), GetTestName())
		zipFilePath := filepath.Join(helpers.TestResultsPath, zipFileName)

		_, err := exec.Command(
			"/usr/bin/env", "bash", "-c",
			fmt.Sprintf("zip -qr \"%s\" \"%s\"", zipFilePath, path)).CombinedOutput()
		if err != nil {
			log.WithError(err).Errorf("cannot create zip file '%s'", zipFilePath)
		}

		GinkgoPrint("[[ATTACHMENT|%s]]", zipFileName)
	}

	if !TestFailed() && helpers.IsRunningOnJenkins() {
		// If the test success delete the monitor.log filename to not store all
		// the data in Jenkins
		testPath, err := helpers.CreateReportDirectory()
		if err != nil {
			log.WithError(err).Error("cannot retrieve test result path")
			return
		}
		_ = os.Remove(filepath.Join(testPath, helpers.MonitorLogFileName))
	}
})
