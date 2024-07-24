// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"bytes"
	"fmt"
	"os"
	"time"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/versioncheck"
	ginkgoext "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers/logutils"
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

	// CheckLogs newtes a new buffer where all the warnings and checks that
	// happens during the test are saved. This buffer will be printed in the
	// test output inside <checks> labels.
	CheckLogs = ginkgoext.NewWriter(new(bytes.Buffer))
)

const (

	// CiliumPath is the path where cilium test code is located.
	CiliumPath = "/src/github.com/cilium/cilium/test"

	// K8sManifestBase tells ginkgo suite where to look for manifests
	K8sManifestBase = "k8s/manifests"

	// VM / Test suite constants.
	K8s     = "k8s"
	K8s1    = "k8s1"
	K8s2    = "k8s2"
	K8s3    = "k8s3"
	Runtime = "runtime"

	Enabled  = "enabled"
	Disabled = "disabled"
	Total    = "total"
	Public   = "public"
	Private  = "private"
	Name     = "Name"

	// CiliumAgentLabel is the label used for Cilium
	CiliumAgentLabel = "k8s-app=cilium"

	// CiliumOperatorLabel is the label used in the Cilium Operator deployment
	CiliumOperatorLabel = "io.cilium/app=operator"

	// HubbleRelayLabel is the label used for the Hubble Relay deployment
	HubbleRelayLabel = "k8s-app=hubble-relay"

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

	// WorldDockerNetwork is the name of the docker network that is *not*
	// managed by Cilium, intended to be treated as "world" for identity
	// purposes (for policy tests).
	WorldDockerNetwork = "world"

	// Names of commonly used containers in tests.
	Httpd1      = "httpd1"
	Httpd2      = "httpd2"
	Httpd3      = "httpd3"
	App1        = "app1"
	App2        = "app2"
	App3        = "app3"
	Client      = "client"
	Server      = "server"
	Host        = "host"
	WorldHttpd1 = "WorldHttpd1"
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
	OptionDebug               = "Debug"
	OptionDropNotify          = "DropNotification"
	OptionTraceNotify         = "TraceNotification"
	OptionIngressPolicy       = "IngressPolicy"
	OptionEgressPolicy        = "EgressPolicy"
	OptionIngress             = "ingress"
	OptionEgress              = "egress"
	OptionNone                = "none"
	OptionDisabled            = "Disabled"
	OptionEnabled             = "Enabled"

	StateTerminating = "Terminating"
	StateRunning     = "Running"

	PingCount   = 5
	PingTimeout = 5

	// CurlConnectTimeout is the timeout for the connect() call that curl
	// invokes
	CurlConnectTimeout = 5

	// CurlMaxTimeout is the hard timeout. It starts when curl is invoked
	// and interrupts curl regardless of whether curl is currently
	// connecting or transferring data. CurlMaxTimeout should be at least 5
	// seconds longer than CurlConnectTimeout to provide some time to
	// actually transfer data.
	CurlMaxTimeout = 20

	DefaultNamespace       = "default"
	KubeSystemNamespace    = "kube-system"
	CiliumNamespaceDefault = KubeSystemNamespace

	TestResultsPath = "test_results/"
	RunDir          = "/var/run/cilium"
	LibDir          = "/var/lib/cilium"

	DaemonName             = "cilium"
	CiliumBugtool          = "cilium-bugtool"
	CiliumBugtoolArgs      = "--exclude-object-files"
	CiliumDockerDaemonName = "cilium-docker"
	AgentDaemon            = "cilium-agent"

	KubectlCreate = ResourceLifeCycleAction("create")
	KubectlDelete = ResourceLifeCycleAction("delete")
	KubectlApply  = ResourceLifeCycleAction("apply")

	KubectlPolicyNameLabel      = k8sConst.PolicyLabelName
	KubectlPolicyNameSpaceLabel = k8sConst.PolicyLabelNamespace

	// CiliumStableHelmChartVersion should be the chart version that points
	// to the v1.X branch
	CiliumStableHelmChartVersion = "1.16"
	CiliumStableVersion          = "v" + CiliumStableHelmChartVersion
	CiliumLatestHelmChartVersion = "1.17.0-dev"

	MonitorLogFileName = "monitor.log"

	// CiliumTestLog is the filename where the cilium logs that happens during
	// the test are saved.
	CiliumTestLog = "cilium-test.log"

	// HubbleRelayTestLog is the filename where the hubble relay logs that happens during
	// the test are saved.
	HubbleRelayTestLog = "hubble-relay-test.log"

	// CiliumOperatorTestLog is the filename where the cilium operator logs that happens during
	// the test are saved.
	CiliumOperatorTestLog = "cilium-operator-test.log"

	// FakeIPv4WorldAddress is an IP which is used in some datapath tests
	// for simulating external IPv4 connectivity.
	FakeIPv4WorldAddress = "192.168.254.254"

	// FakeIPv6WorldAddress is an IP which is used in some datapath tests
	// for simulating external IPv6 connectivity.
	FakeIPv6WorldAddress = "fdff::ff"

	// DockerBridgeIP is the IP on the docker0 bridge
	DockerBridgeIP = "172.17.0.1"

	// SecondaryIface is the name of the secondary iface which can be used to
	// communicate between nodes. The iface is used to attach bpf_netdev.o
	// to test NodePort with multiple devices.
	// Because the name is hardcoded, it cannot be used in tests which run on
	// on EKS/GKE or any other env which hasn't been provisioned with
	// test/Vagrantfile.
	SecondaryIface = "enp0s9"

	// Logs messages that should not be in the cilium logs...
	panicMessage        = "panic:"
	deadLockHeader      = "POTENTIAL DEADLOCK:"                                      // from github.com/sasha-s/go-deadlock/deadlock.go:header
	segmentationFault   = "segmentation fault"                                       // from https://github.com/cilium/cilium/issues/3233
	NACKreceived        = "NACK received for version"                                // from https://github.com/cilium/cilium/issues/4003
	RunInitFailed       = "JoinEP: "                                                 // from https://github.com/cilium/cilium/pull/5052
	sizeMismatch        = "size mismatch for BPF map"                                // from https://github.com/cilium/cilium/issues/7851
	RemovingMapMsg      = "Removing map to allow for property upgrade"               // from https://github.com/cilium/cilium/pull/10626
	logBufferMessage    = "Log buffer too small to dump verifier log"                // from https://github.com/cilium/cilium/issues/10517
	ClangErrorsMsg      = " errors generated."                                       // from https://github.com/cilium/cilium/issues/10857
	ClangErrorMsg       = "1 error generated."                                       // from https://github.com/cilium/cilium/issues/10857
	symbolSubstitution  = "Skipping symbol substitution"                             //
	uninitializedRegen  = "Uninitialized regeneration level"                         // from https://github.com/cilium/cilium/pull/10949
	unstableStat        = "BUG: stat() has unstable behavior"                        // from https://github.com/cilium/cilium/pull/11028
	removeTransientRule = "Unable to process chain CILIUM_TRANSIENT_FORWARD with ip" // from https://github.com/cilium/cilium/issues/11276
	missingIptablesWait = "Missing iptables wait arg (-w):"
	localIDRestoreFail  = "Could not restore all CIDR identities" // from https://github.com/cilium/cilium/pull/19556
	routerIPMismatch    = "Mismatch of router IPs found during restoration"
	emptyIPNodeIDAlloc  = "Attempt to allocate a node ID for an empty node IP address"

	// ...and their exceptions.
	opCantBeFulfilled          = "Operation cannot be fulfilled on leases.coordination.k8s.io"        // cf. https://github.com/cilium/cilium/issues/16402
	initLeaderElection         = "error initially creating leader election record: leases."           // cf. https://github.com/cilium/cilium/issues/16402#issuecomment-861544964
	globalDataSupport          = "kernel doesn't support global data"                                 // cf. https://github.com/cilium/cilium/issues/16418
	removeInexistentID         = "removing identity not added to the identity manager!"               // cf. https://github.com/cilium/cilium/issues/16419
	failedToListCRDs           = "the server could not find the requested resource"                   // cf. https://github.com/cilium/cilium/issues/16425
	retrieveResLock            = "retrieving resource lock kube-system/cilium-operator-resource-lock" // cf. https://github.com/cilium/cilium/issues/16402#issuecomment-871155492
	failedToRelLockEmptyName   = "Failed to release lock: resource name may not be empty"             // cf. https://github.com/cilium/cilium/issues/16402#issuecomment-985819560
	failedToUpdateLock         = "Failed to update lock:"
	failedToReleaseLock        = "Failed to release lock:"
	errorCreatingInitialLeader = "error initially creating leader election record:"
	cantEnableJIT              = "bpf_jit_enable: no such file or directory"                             // Because we run tests in Kind.
	delMissingService          = "Deleting no longer present service"                                    // cf. https://github.com/cilium/cilium/issues/29679
	failedIpcacheRestore       = "Failed to restore existing identities from the previous ipcache"       // cf. https://github.com/cilium/cilium/issues/29328
	podCIDRUnavailable         = " PodCIDR not available"                                                // cf. https://github.com/cilium/cilium/issues/29680
	unableGetNode              = "Unable to get node resource"                                           // cf. https://github.com/cilium/cilium/issues/29710
	disableSocketLBTracing     = "Disabling socket-LB tracing"                                           // cf. https://github.com/cilium/cilium/issues/29734
	sessionAffinitySocketLB    = "Session affinity for host reachable services needs kernel"             // cf. https://github.com/cilium/cilium/issues/29736
	objectHasBeenModified      = "the object has been modified; please apply your changes"               // cf. https://github.com/cilium/cilium/issues/29712
	noBackendResponse          = "The kernel does not support --service-no-backend-response=reject"      // cf. https://github.com/cilium/cilium/issues/29733
	unsupportedSocketLookup    = "Without socket lookup kernel functionality"                            // cf. https://github.com/cilium/cilium/issues/29735
	legacyBGPFeature           = "You are using the legacy BGP feature"                                  // Expected when testing the legacy BGP feature.
	etcdTimeout                = "etcd client timeout exceeded"                                          // cf. https://github.com/cilium/cilium/issues/29714
	endpointRestoreFailed      = "Unable to restore endpoint, ignoring"                                  // cf. https://github.com/cilium/cilium/issues/29716
	failedPeerSync             = "Failed to create peer client for peers synchronization"                // cf. https://github.com/cilium/cilium/issues/29726
	unableRestoreRouterIP      = "Unable to restore router IP from filesystem"                           // cf. https://github.com/cilium/cilium/issues/29715
	routerIPReallocated        = "Router IP could not be re-allocated"                                   // cf. https://github.com/cilium/cilium/issues/29715
	cantFindIdentityInCache    = "unable to release identity: unable to find key in local cache"         // cf. https://github.com/cilium/cilium/issues/29732
	kubeApiserverConnLost1     = ":6443/version\\\": http2: client connection lost"                      // cf. https://github.com/cilium/cilium/issues/29737
	kubeApiserverConnLost2     = ":6443/healthz\\\": http2: client connection lost"                      // cf. https://github.com/cilium/cilium/issues/29737
	heartbeatTimedOut          = "Heartbeat timed out, restarting client connections"                    // cf. https://github.com/cilium/cilium/issues/29737
	keyAllocFailedFoundMaster  = "Found master key after proceeding with new allocation"                 // cf. https://github.com/cilium/cilium/issues/29738
	cantRecreateMasterKey      = "unable to re-create missing master key"                                // cf. https://github.com/cilium/cilium/issues/29738
	cantUpdateCRDIdentity      = "Unable update CRD identity information with a reference for this node" // cf. https://github.com/cilium/cilium/issues/29739
	cantDeleteFromPolicyMap    = "cilium_call_policy: delete: key does not exist"                        // cf. https://github.com/cilium/cilium/issues/29754
	// HelmTemplate is the location of the Helm templates to install Cilium
	HelmTemplate = "../install/kubernetes/cilium"

	// ServiceSuffix is the Kubernetes service suffix
	ServiceSuffix = "svc.cluster.local"
)

var (
	// CiliumNamespace is where cilium should run.
	CiliumNamespace = CiliumNamespaceDefault

	// LogGathererNamespace is where log-gatherer should run. It follows cilium
	// for simplicity.
	LogGathererNamespace = CiliumNamespace
)

// Re-definitions of stable constants in the API. The re-definition is on
// purpose to validate these values in the API. They may never change
const (
	// ReservedIdentityHealth is equivalent to pkg/identity.ReservedIdentityHealth
	ReservedIdentityHealth = 4

	// ReservedIdentityHost is equivalent to pkg/identity.ReservedIdentityHost
	ReservedIdentityHost = 1
)

var (
	IsCiliumV1_8  = versioncheck.MustCompile(">=1.7.90 <1.9.0")
	IsCiliumV1_9  = versioncheck.MustCompile(">=1.8.90 <1.10.0")
	IsCiliumV1_10 = versioncheck.MustCompile(">=1.9.90 <1.11.0")
	IsCiliumV1_11 = versioncheck.MustCompile(">=1.10.90 <1.12.0")
	IsCiliumV1_12 = versioncheck.MustCompile(">=1.11.90 <1.13.0")
	IsCiliumV1_13 = versioncheck.MustCompile(">=1.12.90 <1.14.0")
	IsCiliumV1_14 = versioncheck.MustCompile(">=1.13.90 <1.15.0")
	IsCiliumV1_15 = versioncheck.MustCompile(">=1.14.90 <1.16.0")
	IsCiliumV1_16 = versioncheck.MustCompile(">=1.15.90 <1.17.0")
	IsCiliumV1_17 = versioncheck.MustCompile(">=1.16.90 <1.18.0")
)

// badLogMessages is a map which key is a part of a log message which indicates
// a failure if the message does not contain any part from value list.
var badLogMessages = map[string][]string{
	panicMessage:        nil,
	deadLockHeader:      nil,
	segmentationFault:   nil,
	NACKreceived:        nil,
	RunInitFailed:       {"signal: terminated", "signal: killed"},
	sizeMismatch:        {"globals/cilium_policy"},
	RemovingMapMsg:      nil,
	logBufferMessage:    nil,
	ClangErrorsMsg:      nil,
	ClangErrorMsg:       nil,
	symbolSubstitution:  nil,
	uninitializedRegen:  nil,
	unstableStat:        nil,
	removeTransientRule: nil,
	missingIptablesWait: nil,
	localIDRestoreFail:  nil,
	routerIPMismatch:    nil,
	emptyIPNodeIDAlloc:  nil,
	"DATA RACE":         nil,
	// Exceptions for level=error should only be added as a last resort, if the
	// error cannot be fixed in Cilium or in the test.
	logutils.ErrorLogs: {opCantBeFulfilled, initLeaderElection, globalDataSupport,
		removeInexistentID, failedToListCRDs, retrieveResLock, failedToRelLockEmptyName,
		failedToUpdateLock, failedToReleaseLock, errorCreatingInitialLeader},
	logutils.WarningLogs: {cantEnableJIT, delMissingService, failedIpcacheRestore,
		podCIDRUnavailable, unableGetNode,
		disableSocketLBTracing, sessionAffinitySocketLB, objectHasBeenModified, noBackendResponse,
		unsupportedSocketLookup, legacyBGPFeature, etcdTimeout, endpointRestoreFailed,
		failedPeerSync, unableRestoreRouterIP, routerIPReallocated,
		cantFindIdentityInCache, kubeApiserverConnLost1, kubeApiserverConnLost2, heartbeatTimedOut,
		keyAllocFailedFoundMaster, cantRecreateMasterKey, cantUpdateCRDIdentity,
		cantDeleteFromPolicyMap, failedToListCRDs},
}

var ciliumCLICommands = map[string]string{
	"cilium-dbg endpoint list -o json":          "endpoint_list.txt",
	"cilium-dbg service list -o json":           "service_list.txt",
	"cilium-dbg config":                         "config.txt",
	"sudo cilium-dbg bpf lb list":               "bpf_lb_list.txt",
	"sudo cilium-dbg bpf ct list global":        "bpf_ct_list.txt",
	"sudo cilium-dbg bpf tunnel list":           "bpf_tunnel_list.txt",
	"cilium-dbg policy get":                     "policy_get.txt",
	"cilium-dbg status --all-controllers":       "status.txt",
	"cilium-dbg kvstore get cilium --recursive": "kvstore_get.txt",

	"hubble observe --since 4h -o jsonpb": "hubble_observe.json",
}

// ciliumKubCLICommands these commands are the same as `ciliumCLICommands` but
// it'll run inside a container and it does not have sudo support
var ciliumKubCLICommands = map[string]string{
	"cilium-dbg endpoint list -o json":    "endpoint_list.txt",
	"cilium-dbg service list -o json":     "service_list.txt",
	"cilium-dbg config":                   "config.txt",
	"cilium-dbg bpf lb list":              "bpf_lb_list.txt",
	"cilium-dbg bpf ct list global":       "bpf_ct_list.txt",
	"cilium-dbg bpf tunnel list":          "bpf_tunnel_list.txt",
	"cilium-dbg policy get":               "policy_get.txt",
	"cilium-dbg status --all-controllers": "status.txt",

	"hubble observe --since 4h -o jsonpb": "hubble_observe.json",
}

// ciliumKubCLICommandsKVStore contains commands related to querying the kvstore.
// It is separate from ciliumKubCLICommands because it has a higher likelihood
// of timing out in our CI, so we want to run it separately. Otherwise, we might
// lose out on getting other critical debugging output when a test fails.
var ciliumKubCLICommandsKVStore = map[string]string{
	"cilium-dbg kvstore get cilium --recursive": "kvstore_get.txt",
}

// K8s1VMName is the name of the Kubernetes master node when running K8s tests.
func K8s1VMName() string {
	return fmt.Sprintf("k8s1-%s", GetCurrentK8SEnv())
}

// K8s2VMName is the name of the Kubernetes worker node when running K8s tests.
func K8s2VMName() string {
	return fmt.Sprintf("k8s2-%s", GetCurrentK8SEnv())
}

// GetBadLogMessages returns a deep copy of badLogMessages to allow removing
// messages for specific tests.
func GetBadLogMessages() map[string][]string {
	mapCopy := make(map[string][]string, len(badLogMessages))
	for badMsg, exceptions := range badLogMessages {
		exceptionsCopy := make([]string, len(exceptions))
		copy(exceptionsCopy, exceptions)
		mapCopy[badMsg] = exceptionsCopy
	}
	return mapCopy
}
