// Copyright 2017-2019 Authors of Cilium
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
	"bytes"
	"fmt"
	"os"
	"path"
	"time"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/versioncheck"
	"github.com/cilium/cilium/test/ginkgo-ext"
)

var (
	// HelperTimeout is a predefined timeout value for commands.
	HelperTimeout = 4 * time.Minute

	// ShortCommandTimeout is a timeout for commands which should not take a
	// long time to execute.
	ShortCommandTimeout = 10 * time.Second

	// MidCommandTimeout is a timeout for commands which may take a bit longer
	// than ShortCommandTimeout, but less time than HelperTimeout to execute.
	MidCommandTimeout = 30 * time.Second

	// CiliumStartTimeout is a predefined timeout value for Cilium startup.
	CiliumStartTimeout = 100 * time.Second

	// CiliumBasePath is the absolute path to the cilium source repository
	// in the guest VMs
	CiliumBasePath = "../"

	// BasePath is the path in the Vagrant VMs to which the test directory
	// is mounted
	BasePath = path.Join(CiliumBasePath, "test")

	// CheckLogs newtes a new buffer where all the warnings and checks that
	// happens during the test are saved. This buffer will be printed in the
	// test output inside <checks> labels.
	CheckLogs = ginkgoext.NewWriter(new(bytes.Buffer))
)

const (

	//CiliumPath is the path where cilium test code is located.
	CiliumPath = "/src/github.com/cilium/cilium/test"

	// K8sManifestBase tells ginkgo suite where to look for manifests
	K8sManifestBase = "k8sT/manifests"

	// VM / Test suite constants.
	K8s     = "k8s"
	K8s1    = "k8s1"
	K8s1Ip  = "192.168.36.11"
	K8s2    = "k8s2"
	K8s2Ip  = "192.168.36.12"
	Runtime = "runtime"

	Enabled  = "enabled"
	Disabled = "disabled"
	Total    = "total"
	Public   = "public"
	Private  = "private"
	Name     = "Name"

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

	// CiliumDockerNetwork is the name of the Docker network which Cilium manages.
	CiliumDockerNetwork = "cilium-net"

	// HostDockerNetwork is the name of the host network driver.
	HostDockerNetwork = "host"

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

	// LogPerm is the permission for files that are created by this framework
	// that contain logs, outputs of Cilium CLI commands, etc.
	LogPerm = os.FileMode(0666)

	// Configuration options for endpoints. Copied from endpoint/endpoint.go
	// TODO: these should be converted into types for use in configuration
	// functions instead of using basic strings.

	OptionConntrackAccounting = "ConntrackAccounting"
	OptionConntrackLocal      = "ConntrackLocal"
	OptionConntrack           = "Conntrack"
	OptionDebug               = "Debug"
	OptionDropNotify          = "DropNotification"
	OptionTraceNotify         = "TraceNotification"
	OptionNAT46               = "NAT46"
	OptionIngressPolicy       = "IngressPolicy"
	OptionEgressPolicy        = "EgressPolicy"
	OptionIngress             = "ingress"
	OptionEgress              = "egress"
	OptionNone                = "none"
	OptionDisabled            = "Disabled"
	OptionEnabled             = "Enabled"

	StateTerminating = "Terminating"
	StateRunning     = "Running"

	PingCount = 5

	// CurlConnectTimeout is the timeout for the connect() call that curl
	// invokes
	CurlConnectTimeout = 5

	// CurlMaxTimeout is the hard timeout. It starts when curl is invoked
	// and interrupts curl regardless of whether curl is currently
	// connecting or transferring data. CurlMaxTimeout should be at least 5
	// seconds longer than CurlConnectTimeout to provide some time to
	// actually transfer data.
	CurlMaxTimeout = 8

	DefaultNamespace    = "default"
	KubeSystemNamespace = "kube-system"

	TestResultsPath = "test_results/"
	RunDir          = "/var/run/cilium"
	LibDir          = "/var/lib/cilium"

	DaemonName             = "cilium"
	CiliumBugtool          = "cilium-bugtool"
	CiliumDockerDaemonName = "cilium-docker"
	AgentDaemon            = "cilium-agent"

	GeneratedHTMLManifest   = "html.yaml"
	GeneratedServerManifest = "server.yaml"
	GeneratedClientManifest = "client.yaml"

	KubectlCreate = ResourceLifeCycleAction("create")
	KubectlDelete = ResourceLifeCycleAction("delete")
	KubectlApply  = ResourceLifeCycleAction("apply")

	KubectlPolicyNameLabel      = k8sConst.PolicyLabelName
	KubectlPolicyNameSpaceLabel = k8sConst.PolicyLabelNamespace

	CiliumStableVersion      = "v1.5"
	CiliumStableImageVersion = "cilium/cilium:" + CiliumStableVersion
	CiliumDeveloperImage     = "k8s1:5000/cilium/cilium-dev:latest"

	MonitorLogFileName = "monitor.log"
	microscopeManifest = "microscope.yaml"

	// CiliumTestLog is the filename where the cilium logs that happens during
	// the test are saved.
	CiliumTestLog = "cilium-test.log"

	// FakeIPv4WorldAddress is an IP which is used in some datapath tests
	// for simulating external IPv4 connectivity.
	FakeIPv4WorldAddress = "192.168.254.254"

	// FakeIPv6WorldAddress is an IP which is used in some datapath tests
	// for simulating external IPv6 connectivity.
	FakeIPv6WorldAddress = "fdff::ff"

	// DockerBridgeIP is the IP on the docker0 bridge
	DockerBridgeIP = "172.17.0.1"

	// Logs messages that should not be in the cilium logs.
	panicMessage      = "panic:"
	deadLockHeader    = "POTENTIAL DEADLOCK:"       // from github.com/sasha-s/go-deadlock/deadlock.go:header
	segmentationFault = "segmentation fault"        // from https://github.com/cilium/cilium/issues/3233
	NACKreceived      = "NACK received for version" // from https://github.com/cilium/cilium/issues/4003
	RunInitFailed     = "JoinEP: "                  // from https://github.com/cilium/cilium/pull/5052
	sizeMismatch      = "size mismatch for BPF map" // from https://github.com/cilium/cilium/issues/7851

	// HelmTemplate is the location of the Helm templates to install Cilium
	HelmTemplate = "../install/kubernetes/cilium"
)

// Re-definitions of stable constants in the API. The re-definition is on
// purpose to validate these values in the API. They may never change
const (
	// ReservedIdentityHealth is equivalent to pkg/identity.ReservedIdentityHealth
	ReservedIdentityHealth = 4
)

// NightlyStableUpgradesFrom the cilium images to update from in Nightly test.
var NightlyStableUpgradesFrom = []string{"v1.3"}

var (
	CiliumV1_5 = versioncheck.MustCompile(">=v1.4.90,<v1.6")
	CiliumV1_6 = versioncheck.MustCompile(">=v1.5.90,<v1.7")
)

// CiliumDefaultDSPatch is the default Cilium DaemonSet patch to be used in all tests.
const CiliumDefaultDSPatch = "cilium-ds-patch.yaml"

// CiliumConfigMapPatch is the default Cilium ConfigMap patch to be used in all tests.
const CiliumConfigMapPatch = "cilium-cm-patch.yaml"

// CiliumConfigMapPatchKvstoreAllocator is equivalent to CiliumConfigMapPatch
// except it uses the kvstore-based allocator instead of the CRD-based allocator.
const CiliumConfigMapPatchKvstoreAllocator = "cilium-cm-kvstore-allocator-patch.yaml"

// badLogMessages is a map which key is a part of a log message which indicates
// a failure if the message does not contain any part from value list.
var badLogMessages = map[string][]string{
	panicMessage:      nil,
	deadLockHeader:    nil,
	segmentationFault: nil,
	NACKreceived:      nil,
	RunInitFailed:     {"signal: terminated", "signal: killed"},
	sizeMismatch:      nil,
}

var ciliumCLICommands = map[string]string{
	"cilium endpoint list -o json":          "endpoint_list.txt",
	"cilium service list -o json":           "service_list.txt",
	"cilium config":                         "config.txt",
	"sudo cilium bpf lb list":               "bpf_lb_list.txt",
	"sudo cilium bpf ct list global":        "bpf_ct_list.txt",
	"sudo cilium bpf tunnel list":           "bpf_tunnel_list.txt",
	"cilium policy get":                     "policy_get.txt",
	"cilium status --all-controllers":       "status.txt",
	"cilium kvstore get cilium --recursive": "kvstore_get.txt",
}

// ciliumKubCLICommands these commands are the same as `ciliumCLICommands` but
// it'll run inside a container and it does not have sudo support
var ciliumKubCLICommands = map[string]string{
	"cilium endpoint list -o json":    "endpoint_list.txt",
	"cilium service list -o json":     "service_list.txt",
	"cilium config":                   "config.txt",
	"cilium bpf lb list":              "bpf_lb_list.txt",
	"cilium bpf ct list global":       "bpf_ct_list.txt",
	"cilium bpf tunnel list":          "bpf_tunnel_list.txt",
	"cilium policy get":               "policy_get.txt",
	"cilium status --all-controllers": "status.txt",
}

// ciliumKubCLICommandsKVStore contains commands related to querying the kvstore.
// It is separate from ciliumKubCLICommands because it has a higher likelihood
// of timing out in our CI, so we want to run it separately. Otherwise, we might
// lose out on getting other critical debugging output when a test fails.
var ciliumKubCLICommandsKVStore = map[string]string{
	"cilium kvstore get cilium --recursive": "kvstore_get.txt",
}

const (
	ciliumEtcdOperatorSA   = "cilium-etcd-operator-sa.yaml"
	ciliumEtcdOperatorRBAC = "cilium-etcd-operator-rbac.yaml"
	ciliumEtcdOperator     = "cilium-etcd-operator.yaml"
)

//GetFilePath returns the absolute path of the provided filename
func GetFilePath(filename string) string {
	return fmt.Sprintf("%s/%s", BasePath, filename)
}

// K8s1VMName is the name of the Kubernetes master node when running K8s tests.
func K8s1VMName() string {
	return fmt.Sprintf("k8s1-%s", GetCurrentK8SEnv())
}

// K8s2VMName is the name of the Kubernetes worker node when running K8s tests.
func K8s2VMName() string {
	return fmt.Sprintf("k8s2-%s", GetCurrentK8SEnv())
}
