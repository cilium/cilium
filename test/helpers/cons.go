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

package helpers

import (
	"fmt"
	"time"
)

var (
	// HelperTimeout is a predefined timeout value for commands.
	HelperTimeout time.Duration = 300 // WithTimeout helper translates it to seconds

	// K8s1VMName is the name of the Kubernetes master node when running
	// Kubernetes tests.
	K8s1VMName = fmt.Sprintf("k8s1-%s", GetCurrentK8SEnv())

	// K8s2VMName is the name of the Kubernetes worker node when running
	// Kubernetes tests.
	K8s2VMName = fmt.Sprintf("k8s2-%s", GetCurrentK8SEnv())
)

const (
	// BasePath is the path in the Vagrant VMs to which the test directory
	// is mounted
	BasePath = "/vagrant/"

	// VM / Test suite constants.
	K8s     = "k8s"
	K8s1    = "k8s1"
	K8s2    = "k8s2"
	Runtime = "runtime"

	Enabled  = "enabled"
	Disabled = "disabled"
	Total    = "total"

	// PolicyEnforcement represents the PolicyEnforcement configuration option
	// for the Cilium agent.
	PolicyEnforcement = "PolicyEnforcement"

	// PolicyEnforcementDefault represents the default PolicyEnforcement mode
	// for Cilium.
	PolicyEnforcementDefault = "default"

	// PolicyEnforcementAlways represents the PolicyEnforcement mode
	// for Cilium in which traffic is denied by default even when no policy
	// is imported.
	PolicyEnforcementAlways = "always"

	// PolicyEnforcementNever represents the PolicyEnforcement mode
	// for Cilium in which traffic is always allowed even if there is a policy
	// selecting endpoints.
	PolicyEnforcementNever = "never"

	// Docker Image names

	// CiliumDockerNetwork is the name of the Docker network which Cilium manages.
	CiliumDockerNetwork = "cilium-net"

	// NetperfImage is the Docker image used for performance testing
	NetperfImage = "tgraf/netperf"

	// HttpdImage is the image used for starting an HTTP server.
	HttpdImage = "cilium/demo-httpd"

	// Names of commonly used containers in tests.

	Httpd1 = "httpd1"
	Httpd2 = "httpd2"
	Httpd3 = "httpd3"
	App1   = "app1"
	App2   = "app2"
	App3   = "app3"
	Client = "client"
	Server = "server"
	Host   = "host"

	// Container lifecycle actions.
	Create = "create"
	Delete = "delete"

	// IP Address families.
	IPv4 = "IPv4"
	IPv6 = "IPv6"

	// Configuration options for endpoints. Copied from endpoint/endpoint.go
	// TODO: these should be converted into types for use in configuration
	// functions instead of using basic strings.

	OptionAllowToHost         = "AllowToHost"
	OptionAllowToWorld        = "AllowToWorld"
	OptionConntrackAccounting = "ConntrackAccounting"
	OptionConntrackLocal      = "ConntrackLocal"
	OptionConntrack           = "Conntrack"
	OptionDebug               = "Debug"
	OptionDropNotify          = "DropNotification"
	OptionTraceNotify         = "TraceNotification"
	OptionNAT46               = "NAT46"
	OptionPolicy              = "Policy"

	OptionDisabled = "Disabled"
	OptionEnabled  = "Enabled"

	PingCount          = 5
	CurlConnectTimeout = 5

	DefaultNamespace    = "default"
	KubeSystemNamespace = "kube-system"

	TestResultsPath = "test_results/"
	RunDir          = "/var/run/cilium"
	LibDir          = "/var/lib/cilium"

	DaemonName             = "cilium"
	CiliumDockerDaemonName = "cilium-docker"
	AgentDaemon            = "cilium-agent"
)

var ciliumCLICommands = map[string]string{
	"cilium endpoint list -o json":   "endpoint_list_txt",
	"cilium service list -o json":    "service_list.txt",
	"cilium config":                  "config.txt",
	"sudo cilium bpf lb list":        "bpf_lb_list.txt",
	"sudo cilium bpf ct list global": "bpf_ct_list.txt",
	"sudo cilium bpf tunnel list":    "bpf_tunnel_list.txt",
	"cilium policy get":              "policy_get.txt",
	"cilium status":                  "status.txt",
}

// ciliumKubCLICommands these commands are the same as `ciliumCLICommands` but
// it'll run inside a container and it does not have sudo support
var ciliumKubCLICommands = map[string]string{
	"cilium endpoint list -o json": "endpoint_list_txt",
	"cilium service list -o json":  "service_list.txt",
	"cilium config":                "config.txt",
	"cilium bpf lb list":           "bpf_lb_list.txt",
	"cilium bpf ct list global":    "bpf_ct_list.txt",
	"cilium bpf tunnel list":       "bpf_tunnel_list.txt",
	"cilium policy get":            "policy_get.txt",
	"cilium status":                "status.txt",
}

//GetFilePath returns the absolute path of the provided filename
func GetFilePath(filename string) string {
	return fmt.Sprintf("%s%s", BasePath, filename)
}
