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
	"flag"
	"fmt"
	"os"
	"time"

	. "github.com/onsi/ginkgo"
	ginkgoconfig "github.com/onsi/ginkgo/config"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"

	"testing"

	ginkgoext "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	log "github.com/sirupsen/logrus"
)

var DefaultSettings map[string]string = map[string]string{
	"K8S_VERSION": "1.7",
}

var (
	vagrant     helpers.Vagrant
	reprovision bool
)

func init() {
	log.SetOutput(GinkgoWriter)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: true,
	})

	for k, v := range DefaultSettings {
		getOrSetEnvVar(k, v)
	}

	flag.BoolVar(&reprovision, "cilium.provision", true,
		"Provision Vagrant boxes and Cilium before running test")
}

func TestTest(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter(fmt.Sprintf(
		"%s.xml", ginkgoext.GetScopeWithVersion()))
	RunSpecsWithDefaultAndCustomReporters(
		t, ginkgoext.GetScopeWithVersion(), []Reporter{junitReporter})
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

var _ = BeforeSuite(func() {
	var err error

	if !reprovision {
		// The developer has explicitly told us that they don't care
		// about updating Cilium inside the guest, so skip setup below.
		return
	}

	progressChan := goReportVagrantStatus()
	defer func() { progressChan <- err == nil }()

	switch ginkgoext.GetScope() {
	case "runtime":
		err = vagrant.Create("runtime")
		if err != nil {
			Fail(fmt.Sprintf("Vagrant could not start correctly: %s", err))
		}
		cilium := helpers.CreateCilium("runtime", log.WithFields(
			log.Fields{"testName": "BeforeSuite"}))
		err = cilium.SetUp()
		if err != nil {
			Fail(fmt.Sprintf("Vagrant could not setup cilium correctly: %s", err))
		}

	case "k8s":
		//FIXME: This should be:
		// Start k8s1 and provision kubernetes.
		// When finish, start to build cilium in background
		// Start k8s2
		// Wait until compilation finished, and pull cilium image on k8s2
		err = vagrant.Create(fmt.Sprintf("k8s1-%s", helpers.GetCurrentK8SEnv()))
		if err != nil {
			Fail(fmt.Sprintf("Vagrant k8s1 could not started correctly: %s", err))
		}
		err = vagrant.Create(fmt.Sprintf("k8s2-%s", helpers.GetCurrentK8SEnv()))
		if err != nil {
			Fail(fmt.Sprintf("Vagrant k8s2 could not started correctly: %s", err))
		}
	}
	return
})

var _ = AfterSuite(func() {
	if !helpers.IsRunningOnJenkins() {
		log.Infof("AfterSuite: is dev env, keep templates as it is")
		return
	}

	scope := ginkgoext.GetScope()
	log.Infof("Running After Suite flag for scope='%s'", scope)
	switch scope {
	case "runtime":
		vagrant.Destroy("runtime")
	case "k8s":
		vagrant.Destroy(fmt.Sprintf("k8s1-%s", helpers.GetCurrentK8SEnv()))
		vagrant.Destroy(fmt.Sprintf("k8s2-%s", helpers.GetCurrentK8SEnv()))
	}
	return
})

func getOrSetEnvVar(key, value string) {
	if val := os.Getenv(key); val == "" {
		log.Infof("Init: Env var '%s' was not set, set default value '%s'", key, value)
		os.Setenv(key, value)
	}
}
