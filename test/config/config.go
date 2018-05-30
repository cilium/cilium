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

import "flag"

// CiliumTestConfigType holds all of the configurable elements of the testsuite
type CiliumTestConfigType struct {
	Reprovision      bool
	HoldEnvironment  bool
	SSHConfig        string
	ShowCommands     bool
	CiliumDSManifest string
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
	flag.StringVar(&c.SSHConfig, "cilium.SSHConfig", "",
		"Specify a custom command to fetch SSH configuration (eg: 'vagrant ssh-config')")
	flag.BoolVar(&c.ShowCommands, "cilium.showCommands", false,
		"Output which commands are ran to stdout")
	flag.StringVar(&c.CiliumDSManifest, "cilium.dsManifest", "",
		"Cilium daemon set manifest to use for running the test (only Kubernetes)")

}
