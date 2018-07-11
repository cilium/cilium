// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ciliumTest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/test/config"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	ginkgoext "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	gops "github.com/google/gops/agent"
	"github.com/onsi/ginkgo"
	ginkgoconfig "github.com/onsi/ginkgo/config"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var (
	log             = logging.DefaultLogger
	DefaultSettings = map[string]string{
		"K8S_VERSION": "1.10",
	}
	k8sNodesEnv         = "K8S_NODES"
	commandsLogFileName = "cmds.log"
)

func init() {

	// Open socket for using gops to get stacktraces in case the tests deadlock.
	if err := gops.Listen(gops.Options{}); err != nil {
		errorString := fmt.Sprintf("unable to start gops: %s", err)
		fmt.Println(errorString)
		os.Exit(-1)
	}

	for k, v := range DefaultSettings {
		getOrSetEnvVar(k, v)
	}

	config.CiliumTestConfig.ParseFlags()

	os.RemoveAll(helpers.TestResultsPath)
}

func configLogsOutput() {
	log.SetLevel(logrus.DebugLevel)
	log.Out = &config.TestLogWriter
	logrus.SetFormatter(&config.Formatter)
	log.Formatter = &config.Formatter
	log.Hooks.Add(&config.LogHook{})

	ginkgoext.GinkgoWriter = NewWriter(log.Out)
}

func ShowCommands() {
	if !config.CiliumTestConfig.ShowCommands {
		return
	}

	helpers.SSHMetaLogs = ginkgoext.NewWriter(os.Stdout)
}

func TestTest(t *testing.T) {
	configLogsOutput()
	ShowCommands()

	if config.CiliumTestConfig.CiliumDSManifest != "" {
		helpers.CiliumDSPath = config.CiliumTestConfig.CiliumDSManifest
		log.Info("Using new Cilium daemonset manifest '%s'", helpers.CiliumDSPath)
	}

	if config.CiliumTestConfig.HoldEnvironment {
		RegisterFailHandler(helpers.Fail)
	} else {
		RegisterFailHandler(Fail)
	}
	junitReporter := ginkgoext.NewJUnitReporter(fmt.Sprintf(
		"%s.xml", helpers.GetScopeWithVersion()))
	RunSpecsWithDefaultAndCustomReporters(
		t, helpers.GetScopeWithVersion(), []ginkgo.Reporter{junitReporter})
}

func goReportVagrantStatus() chan bool {
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
			fmt.Printf("\rSpinning up vagrant VMs... %s", out)
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
	ginkgoext.GinkgoPrint(failmsg)
	Fail(failmsg)
}

var _ = BeforeAll(func() {
	var err error

	if !config.CiliumTestConfig.Reprovision {
		// The developer has explicitly told us that they don't care
		// about updating Cilium inside the guest, so skip setup below.
		return
	}

	if config.CiliumTestConfig.SSHConfig != "" {
		// If we set a different VM that it's not in our test environment
		// ginkgo cannot provision it, so skip setup below.
		return
	}

	if progressChan := goReportVagrantStatus(); progressChan != nil {
		defer func() { progressChan <- err == nil }()
	}
	logger := log.WithFields(logrus.Fields{"testName": "BeforeSuite"})

	switch helpers.GetScope() {
	case helpers.Runtime:
		err = helpers.CreateVM(helpers.Runtime)
		if err != nil {
			log.WithError(err).Error("Error starting VM")
			reportCreateVMFailure(helpers.Runtime, err)
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

	case helpers.K8s:
		//FIXME: This should be:
		// Start k8s1 and provision kubernetes.
		// When finish, start to build cilium in background
		// Start k8s2
		// Wait until compilation finished, and pull cilium image on k8s2

		// Name for K8s VMs depends on K8s version that is running.

		err = helpers.CreateVM(helpers.K8s1VMName())
		if err != nil {
			reportCreateVMFailure(helpers.K8s1VMName(), err)
		}

		err = helpers.CreateVM(helpers.K8s2VMName())
		if err != nil {
			reportCreateVMFailure(helpers.K8s2VMName(), err)
		}

		// For Nightly test we need to have more than two kubernetes nodes. If
		// the env variable K8S_NODES is present, more nodes will be created.
		if nodes := os.Getenv(k8sNodesEnv); nodes != "" {
			nodesInt, err := strconv.Atoi(nodes)
			if err != nil {
				Fail(fmt.Sprintf("%s value is not a number %q", k8sNodesEnv, nodes))
			}
			for i := 3; i <= nodesInt; i++ {
				vmName := fmt.Sprintf("%s%d-%s", helpers.K8s, i, helpers.GetCurrentK8SEnv())
				err = helpers.CreateVM(vmName)
				if err != nil {
					reportCreateVMFailure(vmName, err)
				}
			}
		}
		kubectl := helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		kubectl.Apply(helpers.GetFilePath("../examples/kubernetes/prometheus.yaml"))
	}
	return
})

var _ = AfterAll(func() {
	if !helpers.IsRunningOnJenkins() {
		log.Infof("AfterSuite: not running on Jenkins; leaving VMs running for debugging")
		return
	}

	scope := helpers.GetScope()
	log.Infof("cleaning up VMs started for %s tests", scope)
	switch scope {
	case helpers.Runtime:
		helpers.DestroyVM(helpers.Runtime)
	case helpers.K8s:
		helpers.DestroyVM(helpers.K8s1VMName())
		helpers.DestroyVM(helpers.K8s2VMName())
	}
	return
})

func getOrSetEnvVar(key, value string) {
	if val := os.Getenv(key); val == "" {
		log.Infof("environment variable %q was not set; setting to default value %q", key, value)
		os.Setenv(key, value)
	}
}

var _ = AfterEach(func() {

	defer config.TestLogWriterReset()
	err := helpers.CreateLogFile(config.TestLogFileName, config.TestLogWriter.Bytes())
	if err != nil {
		log.WithError(err).Errorf("cannot create log file '%s'", config.TestLogFileName)
		return
	}

	defer helpers.SSHMetaLogs.Reset()
	err = helpers.CreateLogFile(commandsLogFileName, helpers.SSHMetaLogs.Bytes())
	if err != nil {
		log.WithError(err).Errorf("cannot create log file '%s'", commandsLogFileName)
		return
	}

	// This piece of code is to enable zip attachments on Junit Output.
	if ginkgo.CurrentGinkgoTestDescription().Failed && helpers.IsRunningOnJenkins() {
		// ReportDirectory is already created. No check the error
		path, _ := helpers.CreateReportDirectory()
		zipFileName := fmt.Sprintf("%s_%s.zip", helpers.MakeUID(), ginkgoext.GetTestName())
		zipFilePath := filepath.Join(helpers.TestResultsPath, zipFileName)

		_, err := exec.Command(
			"/bin/bash", "-c",
			fmt.Sprintf("zip -qr %s %s", zipFilePath, path)).CombinedOutput()
		if err != nil {
			log.WithError(err).Errorf("cannot create zip file '%s'", zipFilePath)
		}

		ginkgoext.GinkgoPrint("[[ATTACHMENT|%s]]", zipFileName)
	}

	if !ginkgo.CurrentGinkgoTestDescription().Failed && helpers.IsRunningOnJenkins() {
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
