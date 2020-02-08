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

package config

import (
	"flag"
	"time"
)

// CiliumTestConfigType holds all of the configurable elements of the testsuite
type CiliumTestConfigType struct {
	Reprovision bool
	// HoldEnvironment leaves the test infrastructure in place on failure
	HoldEnvironment bool
	// PassCLIEnvironment passes through the environment invoking the gingko
	// tests. When false all subcommands are executed with an empty environment,
	// including PATH.
	PassCLIEnvironment  bool
	SSHConfig           string
	ShowCommands        bool
	TestScope           string
	SkipLogGathering    bool
	CiliumImage         string
	CiliumOperatorImage string
	ProvisionK8s        bool
	Timeout             time.Duration
	Kubeconfig          string
	Registry            string
	Benchmarks          bool
}

// CiliumTestConfig holds the global configuration of commandline flags
// in the ginkgo-based testing environment.
var CiliumTestConfig = CiliumTestConfigType{}

// ParseFlags parses commandline flags relevant to testing.
func (c *CiliumTestConfigType) ParseFlags() {
	flag.BoolVar(&c.Reprovision, "cilium.provision", true,
		"Provision Vagrant boxes and Cilium before running test")
	flag.BoolVar(&c.HoldEnvironment, "cilium.holdEnvironment", false,
		"On failure, hold the environment in its current state")
	flag.BoolVar(&c.PassCLIEnvironment, "cilium.passCLIEnvironment", false,
		"Pass the environment invoking ginkgo, including PATH, to subcommands")
	flag.BoolVar(&c.SkipLogGathering, "cilium.skipLogs", false,
		"skip gathering logs if a test fails")
	flag.StringVar(&c.SSHConfig, "cilium.SSHConfig", "",
		"Specify a custom command to fetch SSH configuration (eg: 'vagrant ssh-config')")
	flag.BoolVar(&c.ShowCommands, "cilium.showCommands", false,
		"Output which commands are ran to stdout")
	flag.StringVar(&c.TestScope, "cilium.testScope", "",
		"Specifies scope of test to be ran (k8s, Nightly, runtime)")
	flag.StringVar(&c.CiliumImage, "cilium.image", "",
		"Specifies which image of cilium to use during tests")
	flag.StringVar(&c.CiliumOperatorImage, "cilium.operator-image", "",
		"Specifies which image of cilium-operator to use during tests")
	flag.BoolVar(&c.ProvisionK8s, "cilium.provision-k8s", true,
		"Specifies whether Kubernetes should be deployed and installed via kubeadm or not")
	flag.DurationVar(&c.Timeout, "cilium.timeout", 24*time.Hour,
		"Specifies timeout for test run")
	flag.StringVar(&c.Kubeconfig, "cilium.kubeconfig", "",
		"Kubeconfig to be used for k8s tests")
	flag.StringVar(&c.Registry, "cilium.registry", "k8s1:5000", "docker registry hostname for Cilium image")
	flag.BoolVar(&c.Benchmarks, "cilium.benchmarks", false,
		"Specifies benchmark tests should be run which may increase test time")
}
