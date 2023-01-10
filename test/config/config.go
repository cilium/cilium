// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"flag"
	"os"
	"strings"
	"time"
)

const (
	RegistryDomain     = "docker.io"
	RegistrySecretName = "regcred"
)

// CiliumTestConfigType holds all of the configurable elements of the testsuite
type CiliumTestConfigType struct {
	Reprovision bool
	// HoldEnvironment leaves the test infrastructure in place on failure
	HoldEnvironment bool
	// PassCLIEnvironment passes through the environment invoking the gingko
	// tests. When false all subcommands are executed with an empty environment,
	// including PATH.
	PassCLIEnvironment   bool
	SSHConfig            string
	ShowCommands         bool
	TestScope            string
	SkipLogGathering     bool
	CiliumImage          string
	CiliumTag            string
	CiliumOperatorImage  string
	CiliumOperatorTag    string
	CiliumOperatorSuffix string
	HubbleRelayImage     string
	HubbleRelayTag       string
	ProvisionK8s         bool
	Timeout              time.Duration
	Kubeconfig           string
	KubectlPath          string
	RegistryCredentials  string
	// Multinode enables the running of tests that involve more than one
	// node. If false, some tests will silently skip multinode checks.
	Multinode      bool
	RunQuarantined bool
	Help           bool
}

// CiliumTestConfig holds the global configuration of commandline flags
// in the ginkgo-based testing environment.
var CiliumTestConfig = CiliumTestConfigType{}

// ParseFlags parses commandline flags relevant to testing.
func (c *CiliumTestConfigType) ParseFlags() {
	flagset := flag.NewFlagSet("cilium", flag.ExitOnError)
	flagset.BoolVar(&c.Reprovision, "cilium.provision", true,
		"Provision Vagrant boxes and Cilium before running test")
	flagset.BoolVar(&c.HoldEnvironment, "cilium.holdEnvironment", false,
		"On failure, hold the environment in its current state")
	flagset.BoolVar(&c.PassCLIEnvironment, "cilium.passCLIEnvironment", false,
		"Pass the environment invoking ginkgo, including PATH, to subcommands")
	flagset.BoolVar(&c.SkipLogGathering, "cilium.skipLogs", false,
		"skip gathering logs if a test fails")
	flagset.StringVar(&c.SSHConfig, "cilium.SSHConfig", "",
		"Specify a custom command to fetch SSH configuration (eg: 'vagrant ssh-config')")
	flagset.BoolVar(&c.ShowCommands, "cilium.showCommands", false,
		"Output which commands are ran to stdout")
	flagset.StringVar(&c.TestScope, "cilium.testScope", "",
		"Specifies scope of test to be ran (k8s, runtime)")
	flagset.StringVar(&c.CiliumImage, "cilium.image", "",
		"Specifies which image of cilium to use during tests")
	flagset.StringVar(&c.CiliumTag, "cilium.tag", "",
		"Specifies which tag of cilium to use during tests")
	flagset.StringVar(&c.CiliumOperatorImage, "cilium.operator-image", "",
		"Specifies which image of cilium-operator to use during tests")
	flagset.StringVar(&c.CiliumOperatorTag, "cilium.operator-tag", "",
		"Specifies which tag of cilium-operator to use during tests")
	flagset.StringVar(&c.CiliumOperatorSuffix, "cilium.operator-suffix", "-ci",
		"Specifies a suffix to append to operator image after cloud-specific suffix")
	flagset.StringVar(&c.HubbleRelayImage, "cilium.hubble-relay-image", "",
		"Specifies which image of hubble-relay to use during tests")
	flagset.StringVar(&c.HubbleRelayTag, "cilium.hubble-relay-tag", "",
		"Specifies which tag of hubble-relay to use during tests")
	flagset.BoolVar(&c.ProvisionK8s, "cilium.provision-k8s", true,
		"Specifies whether Kubernetes should be deployed and installed via kubeadm or not")
	flagset.DurationVar(&c.Timeout, "cilium.timeout", 24*time.Hour,
		"Specifies timeout for test run")
	flagset.StringVar(&c.Kubeconfig, "cilium.kubeconfig", "",
		"Kubeconfig to be used for k8s tests")
	flagset.StringVar(&c.KubectlPath, "cilium.kubectl-path", "/tmp/kubectl",
		"Path that holds version-specific kubectl binaries")
	flagset.StringVar(&c.RegistryCredentials, "cilium.registryCredentials", "",
		"Registry credentials to be used to download images")
	flagset.BoolVar(&c.Multinode, "cilium.multinode", true,
		"Enable tests across multiple nodes. If disabled, such tests may silently pass")
	flagset.BoolVar(&c.RunQuarantined, "cilium.runQuarantined", false,
		"Run tests that are under quarantine.")
	flagset.BoolVar(&c.Help, "cilium.help", false, "Display this help message.")

	args := make([]string, 0, len(os.Args))
	for index, flag := range os.Args {
		if flag == "-cilium.help" {
			flagset.PrintDefaults()
			os.Exit(1)
		} else if strings.Contains(flag, "-cilium") {
			args = append(args, flag)
			os.Args[index] = ""
		}
	}

	flagset.Parse(args)
}
