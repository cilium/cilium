// Copyright 2016-2019 Authors of Cilium
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

package option

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "config")
)

const (
	// AccessLog is the path to access log of supported L7 requests observed
	AccessLog = "access-log"

	// AgentLabels are additional labels to identify this agent
	AgentLabels = "agent-labels"

	// AllowICMPFragNeeded allows ICMP Fragmentation Needed type packets in policy.
	AllowICMPFragNeeded = "allow-icmp-frag-needed"

	// AllowLocalhost is the policy when to allow local stack to reach local endpoints { auto | always | policy }
	AllowLocalhost = "allow-localhost"

	// AllowLocalhostAuto defaults to policy except when running in
	// Kubernetes where it then defaults to "always"
	AllowLocalhostAuto = "auto"

	// AllowLocalhostAlways always allows the local stack to reach local
	// endpoints
	AllowLocalhostAlways = "always"

	// AllowLocalhostPolicy requires a policy rule to allow the local stack
	// to reach particular endpoints or policy enforcement must be
	// disabled.
	AllowLocalhostPolicy = "policy"

	// AnnotateK8sNode enables annotating a kubernetes node while bootstrapping
	// the daemon, which can also be disbled using this option.
	AnnotateK8sNode = "annotate-k8s-node"

	// AwsInstanceLimitMapping allows overwirting AWS instance limits defined in
	// pkg/aws/eni/limits.go
	// e.g. {"a1.medium": "2,4,4", "a2.custom2": "4,5,6"}
	AwsInstanceLimitMapping = "aws-instance-limit-mapping"

	// AwsReleaseExcessIps allows releasing excess free IP addresses from ENI.
	// Enabling this option reduces waste of IP addresses but may increase
	// the number of API calls to AWS EC2 service.
	AwsReleaseExcessIps = "aws-release-excess-ips"

	// BPFRoot is the Path to BPF filesystem
	BPFRoot = "bpf-root"

	// CertsDirectory is the root directory used to find out certificates used
	// in L7 HTTPs policy enforcement.
	CertsDirectory = "certificates-directory"

	// CGroupRoot is the path to Cgroup2 filesystem
	CGroupRoot = "cgroup-root"

	// ConfigFile is the Configuration file (default "$HOME/ciliumd.yaml")
	ConfigFile = "config"

	// ConfigDir is the directory that contains a file for each option where
	// the filename represents the option name and the content of that file
	// represents the value of that option.
	ConfigDir = "config-dir"

	// ConntrackGarbageCollectorIntervalDeprecated is the deprecated option
	// name to set the conntrack gc interval
	ConntrackGarbageCollectorIntervalDeprecated = "conntrack-garbage-collector-interval"

	// ConntrackGCInterval is the name of the ConntrackGCInterval option
	ConntrackGCInterval = "conntrack-gc-interval"

	// ContainerRuntime sets the container runtime(s) used by Cilium
	// { containerd | crio | docker | none | auto } ( "auto" uses the container
	// runtime found in the order: "docker", "containerd", "crio" )
	// Deprecated: This option is no longer available since cilium-daemon does
	//             not have any direct interaction with container runtimes.
	ContainerRuntime = "container-runtime"

	// ContainerRuntimeEndpoint set the container runtime(s) endpoint(s)
	// Deprecated: This option is no longer available since cilium-daemon does
	//             not have any direct interaction with container runtimes.
	ContainerRuntimeEndpoint = "container-runtime-endpoint"

	// DebugArg is the argument enables debugging mode
	DebugArg = "debug"

	// DebugVerbose is the argument enables verbose log message for particular subsystems
	DebugVerbose = "debug-verbose"

	// Device facing cluster/external network for direct L3 (non-overlay mode)
	Device = "device"

	// DisableConntrack disables connection tracking
	DisableConntrack = "disable-conntrack"

	// DisableEnvoyVersionCheck do not perform Envoy binary version check on startup
	DisableEnvoyVersionCheck = "disable-envoy-version-check"

	// Docker is the path to docker runtime socket (DEPRECATED: use container-runtime-endpoint instead)
	Docker = "docker"

	// EnablePolicy enables policy enforcement in the agent.
	EnablePolicy = "enable-policy"

	// EnableExternalIPs enables implementation of k8s services with externalIPs in datapath
	EnableExternalIPs = "enable-external-ips"

	// K8sEnableEndpointSlice enables the k8s EndpointSlice feature into Cilium
	K8sEnableEndpointSlice = "enable-k8s-endpoint-slice"

	// EnableL7Proxy is the name of the option to enable L7 proxy
	EnableL7Proxy = "enable-l7-proxy"

	// EnableTracing enables tracing mode in the agent.
	EnableTracing = "enable-tracing"

	// EncryptInterface enables encryption on specified interface
	EncryptInterface = "encrypt-interface"

	// EncryptNode enables node IP encryption
	EncryptNode = "encrypt-node"

	// EnvoyLog sets the path to a separate Envoy log file, if any
	EnvoyLog = "envoy-log"

	// FixedIdentityMapping is the key-value for the fixed identity mapping
	// which allows to use reserved label for fixed identities
	FixedIdentityMapping = "fixed-identity-mapping"

	// IPv4ClusterCIDRMaskSize is the mask size for the cluster wide CIDR
	IPv4ClusterCIDRMaskSize = "ipv4-cluster-cidr-mask-size"

	// IPv4Range is the per-node IPv4 endpoint prefix, e.g. 10.16.0.0/16
	IPv4Range = "ipv4-range"

	// IPv6Range is the per-node IPv6 endpoint prefix, must be /96, e.g. fd02:1:1::/96
	IPv6Range = "ipv6-range"

	// IPv4ServiceRange is the Kubernetes IPv4 services CIDR if not inside cluster prefix
	IPv4ServiceRange = "ipv4-service-range"

	// IPv6ServiceRange is the Kubernetes IPv6 services CIDR if not inside cluster prefix
	IPv6ServiceRange = "ipv6-service-range"

	// ModePreFilterNative for loading progs with xdpdrv
	ModePreFilterNative = "native"

	// ModePreFilterGeneric for loading progs with xdpgeneric
	ModePreFilterGeneric = "generic"

	// IPv6ClusterAllocCIDRName is the name of the IPv6ClusterAllocCIDR option
	IPv6ClusterAllocCIDRName = "ipv6-cluster-alloc-cidr"

	// K8sRequireIPv4PodCIDRName is the name of the K8sRequireIPv4PodCIDR option
	K8sRequireIPv4PodCIDRName = "k8s-require-ipv4-pod-cidr"

	// K8sRequireIPv6PodCIDRName is the name of the K8sRequireIPv6PodCIDR option
	K8sRequireIPv6PodCIDRName = "k8s-require-ipv6-pod-cidr"

	// K8sForceJSONPatch when set, uses JSON Patch to update CNP and CEP
	// status in kube-apiserver.
	K8sForceJSONPatch = "k8s-force-json-patch"

	// K8sWatcherEndpointSelector specifies the k8s endpoints that Cilium
	// should watch for.
	K8sWatcherEndpointSelector = "k8s-watcher-endpoint-selector"

	// K8sAPIServer is the kubernetes api address server (for https use --k8s-kubeconfig-path instead)
	K8sAPIServer = "k8s-api-server"

	// K8sKubeConfigPath is the absolute path of the kubernetes kubeconfig file
	K8sKubeConfigPath = "k8s-kubeconfig-path"

	// K8sServiceCacheSize is service cache size for cilium k8s package.
	K8sServiceCacheSize = "k8s-service-cache-size"

	// K8sWatcherQueueSize is the queue size used to serialize each k8s event type
	K8sWatcherQueueSize = "k8s-watcher-queue-size"

	// KeepConfig when restoring state, keeps containers' configuration in place
	KeepConfig = "keep-config"

	// KeepBPFTemplates do not restore BPF template files from binary
	// Deprecated: This option is no longer available since cilium-agent does
	//             not include the BPF templates anymore.
	KeepBPFTemplates = "keep-bpf-templates"

	// KVStore key-value store type
	KVStore = "kvstore"

	// KVStoreOpt key-value store options
	KVStoreOpt = "kvstore-opt"

	// Labels is the list of label prefixes used to determine identity of an endpoint
	Labels = "labels"

	// LabelPrefixFile is the valid label prefixes file path
	LabelPrefixFile = "label-prefix-file"

	// EnableNodePort enables NodePort services implemented by Cilium in BPF
	EnableNodePort = "enable-node-port"

	// NodePortMode indicates in which mode NodePort implementation should run
	// ("snat" or "dsr")
	NodePortMode = "node-port-mode"

	// KubeProxyReplacement controls how to enable kube-proxy replacement
	// features in BPF datapath
	KubeProxyReplacement = "kube-proxy-replacement"

	// NodePortRange defines a custom range where to look up NodePort services
	NodePortRange = "node-port-range"

	// LibDir enables the directory path to store runtime build environment
	LibDir = "lib-dir"

	// LogDriver sets logging endpoints to use for example syslog, fluentd
	LogDriver = "log-driver"

	// LogOpt sets log driver options for cilium
	LogOpt = "log-opt"

	// Logstash enables logstash integration
	Logstash = "logstash"

	// NAT46Range is the IPv6 prefix to map IPv4 addresses to
	NAT46Range = "nat46-range"

	// Masquerade are the packets from endpoints leaving the host
	Masquerade = "masquerade"

	// InstallIptRules sets whether Cilium should install any iptables in general
	InstallIptRules = "install-iptables-rules"

	// IPv6NodeAddr is the IPv6 address of node
	IPv6NodeAddr = "ipv6-node"

	// IPv4NodeAddr is the IPv4 address of node
	IPv4NodeAddr = "ipv4-node"

	// Restore restores state, if possible, from previous daemon
	Restore = "restore"

	// SidecarHTTPProxy disable host HTTP proxy, assuming proxies in sidecar containers
	SidecarHTTPProxy = "sidecar-http-proxy"

	// SidecarIstioProxyImage regular expression matching compatible Istio sidecar istio-proxy container image names
	SidecarIstioProxyImage = "sidecar-istio-proxy-image"

	// SocketPath sets daemon's socket path to listen for connections
	SocketPath = "socket-path"

	// StateDir is the directory path to store runtime state
	StateDir = "state-dir"

	// TracePayloadlen length of payload to capture when tracing
	TracePayloadlen = "trace-payloadlen"

	// Version prints the version information
	Version = "version"

	// FlannelMasterDevice installs a BPF program to allow for policy
	// enforcement in the given network interface. Allows to run Cilium on top
	// of other CNI plugins that provide networking, e.g. flannel, where for
	// flannel, this value should be set with 'cni0'. [EXPERIMENTAL]")
	FlannelMasterDevice = "flannel-master-device"

	// FlannelUninstallOnExit should be used along the flannel-master-device flag,
	// it cleans up all BPF programs installed when Cilium agent is terminated.
	FlannelUninstallOnExit = "flannel-uninstall-on-exit"

	// FlannelManageExistingContainers sets if Cilium should install the BPF
	// programs on already running interfaces created by flannel. Require
	// Cilium to be running in the hostPID.
	// Deprecated: This option is no longer available since cilium-daemon does
	//             not have any direct interaction with container runtimes.
	FlannelManageExistingContainers = "flannel-manage-existing-containers"

	// PProf enables serving the pprof debugging API
	PProf = "pprof"

	// PrefilterDevice is the device facing external network for XDP prefiltering
	PrefilterDevice = "prefilter-device"

	// PrefilterMode { "+ModePreFilterNative+" | "+ModePreFilterGeneric+" } (default: "+option.ModePreFilterNative+")
	PrefilterMode = "prefilter-mode"

	// PrometheusServeAddr IP:Port on which to serve prometheus metrics (pass ":Port" to bind on all interfaces, "" is off)
	PrometheusServeAddr = "prometheus-serve-addr"

	// PrometheusServeAddrDeprecated IP:Port on which to serve prometheus metrics (pass ":Port" to bind on all interfaces, "" is off)
	PrometheusServeAddrDeprecated = "prometheus-serve-addr-deprecated"

	// CMDRef is the path to cmdref output directory
	CMDRef = "cmdref"

	// ToFQDNsMinTTL is the minimum time, in seconds, to use DNS data for toFQDNs policies.
	ToFQDNsMinTTL = "tofqdns-min-ttl"

	// ToFQDNsProxyPort is the global port on which the in-agent DNS proxy should listen. Default 0 is a OS-assigned port.
	ToFQDNsProxyPort = "tofqdns-proxy-port"

	// ToFQDNsEnablePoller enables proactive polling of DNS names in toFQDNs.matchName rules.
	ToFQDNsEnablePoller = "tofqdns-enable-poller"

	// ToFQDNsEmitPollerEvents controls if poller lookups are sent as monitor events
	ToFQDNsEnablePollerEvents = "tofqdns-enable-poller-events"

	// ToFQDNsMaxIPsPerHost defines the maximum number of IPs to maintain
	// for each FQDN name in an endpoint's FQDN cache
	ToFQDNsMaxIPsPerHost = "tofqdns-endpoint-max-ip-per-hostname"

	// ToFQDNsMaxDeferredConnectionDeletes defines the maximum number of IPs to
	// retain for expired DNS lookups with still-active connections"
	ToFQDNsMaxDeferredConnectionDeletes = "tofqdns-max-deferred-connection-deletes"

	// ToFQDNsPreCache is a path to a file with DNS cache data to insert into the
	// global cache on startup.
	// The file is not re-read after agent start.
	ToFQDNsPreCache = "tofqdns-pre-cache"

	// MTUName is the name of the MTU option
	MTUName = "mtu"

	// DatapathMode is the name of the DatapathMode option
	DatapathMode = "datapath-mode"

	// IpvlanMasterDevice is the name of the IpvlanMasterDevice option
	IpvlanMasterDevice = "ipvlan-master-device"

	// EnableHostReachableServices is the name of the EnableHostReachableServices option
	EnableHostReachableServices = "enable-host-reachable-services"

	// HostReachableServicesProtos is the name of the HostReachableServicesProtos option
	HostReachableServicesProtos = "host-reachable-services-protos"

	// HostServicesTCP is the name of EnableHostServicesTCP config
	HostServicesTCP = "tcp"

	// HostServicesUDP is the name of EnableHostServicesUDP config
	HostServicesUDP = "udp"

	// TunnelName is the name of the Tunnel option
	TunnelName = "tunnel"

	// SingleClusterRouteName is the name of the SingleClusterRoute option
	//
	// SingleClusterRoute enables use of a single route covering the entire
	// cluster CIDR to point to the cilium_host interface instead of using
	// a separate route for each cluster node CIDR. This option is not
	// compatible with Tunnel=TunnelDisabled
	SingleClusterRouteName = "single-cluster-route"

	// MonitorAggregationName specifies the MonitorAggregationLevel on the
	// comandline.
	MonitorAggregationName = "monitor-aggregation"

	// MonitorAggregationInterval configures interval for monitor-aggregation
	MonitorAggregationInterval = "monitor-aggregation-interval"

	// MonitorAggregationFlags configures TCP flags used by monitor aggregation.
	MonitorAggregationFlags = "monitor-aggregation-flags"

	// ciliumEnvPrefix is the prefix used for environment variables
	ciliumEnvPrefix = "CILIUM_"

	// ClusterName is the name of the ClusterName option
	ClusterName = "cluster-name"

	// ClusterIDName is the name of the ClusterID option
	ClusterIDName = "cluster-id"

	// ClusterIDMin is the minimum value of the cluster ID
	ClusterIDMin = 0

	// ClusterIDMax is the maximum value of the cluster ID
	ClusterIDMax = 255

	// ClusterMeshConfigName is the name of the ClusterMeshConfig option
	ClusterMeshConfigName = "clustermesh-config"

	// BPFCompileDebugName is the name of the option to enable BPF compiliation debugging
	BPFCompileDebugName = "bpf-compile-debug"

	// CTMapEntriesGlobalTCP retains the Cilium 1.2 (or earlier) size to
	// minimize disruption during upgrade.
	CTMapEntriesGlobalTCPDefault = 1000000
	CTMapEntriesGlobalAnyDefault = 2 << 17 // 256Ki
	CTMapEntriesGlobalTCPName    = "bpf-ct-global-tcp-max"
	CTMapEntriesGlobalAnyName    = "bpf-ct-global-any-max"

	// CTMapEntriesTimeout* name option and default value mappings
	CTMapEntriesTimeoutSYNName    = "bpf-ct-timeout-regular-tcp-syn"
	CTMapEntriesTimeoutFINName    = "bpf-ct-timeout-regular-tcp-fin"
	CTMapEntriesTimeoutTCPName    = "bpf-ct-timeout-regular-tcp"
	CTMapEntriesTimeoutAnyName    = "bpf-ct-timeout-regular-any"
	CTMapEntriesTimeoutSVCTCPName = "bpf-ct-timeout-service-tcp"
	CTMapEntriesTimeoutSVCAnyName = "bpf-ct-timeout-service-any"

	// NATMapEntriesGlobalDefault holds the default size of the NAT map
	// and is 2/3 of the full CT size as a heuristic
	NATMapEntriesGlobalDefault = int((CTMapEntriesGlobalTCPDefault + CTMapEntriesGlobalAnyDefault) * 2 / 3)

	// LimitTableMin defines the minimum CT or NAT table limit
	LimitTableMin = 1 << 10 // 1Ki entries

	// LimitTableMax defines the maximum CT or NAT table limit
	LimitTableMax = 1 << 24 // 16Mi entries (~1GiB of entries per map)

	// NATMapEntriesGlobalName configures max entries for BPF NAT table
	NATMapEntriesGlobalName = "bpf-nat-global-max"

	// PolicyMapEntriesName configures max entries for BPF policymap.
	PolicyMapEntriesName = "bpf-policy-map-max"

	// LogSystemLoadConfigName is the name of the option to enable system
	// load loggging
	LogSystemLoadConfigName = "log-system-load"

	// PrependIptablesChainsName is the name of the option to enable
	// prepending iptables chains instead of appending
	PrependIptablesChainsName = "prepend-iptables-chains"

	// DisableCiliumEndpointCRDName is the name of the option to disable
	// use of the CEP CRD
	DisableCiliumEndpointCRDName = "disable-endpoint-crd"

	// DisableK8sServices disables east-west K8s load balancing by cilium
	DisableK8sServices = "disable-k8s-services"

	// MaxCtrlIntervalName and MaxCtrlIntervalNameEnv allow configuration
	// of MaxControllerInterval.
	MaxCtrlIntervalName = "max-controller-interval"

	// SockopsEnableName is the name of the option to enable sockops
	SockopsEnableName = "sockops-enable"

	// K8sNamespaceName is the name of the K8sNamespace option
	K8sNamespaceName = "k8s-namespace"

	// EnableIPv4Name is the name of the option to enable IPv4 support
	EnableIPv4Name = "enable-ipv4"

	// LegacyDisableIPv4Name is the name of the legacy option to disable
	// IPv4 support
	LegacyDisableIPv4Name = "disable-ipv4"

	// EnableIPv6Name is the name of the option to enable IPv6 support
	EnableIPv6Name = "enable-ipv6"

	// MonitorQueueSizeName is the name of the option MonitorQueueSize
	MonitorQueueSizeName = "monitor-queue-size"

	//FQDNRejectResponseCode is the name for the option for dns-proxy reject response code
	FQDNRejectResponseCode = "tofqdns-dns-reject-response-code"

	// FQDNProxyDenyWithNameError is useful when stub resolvers, like the one
	// in Alpine Linux's libc (musl), treat a REFUSED as a resolution error.
	// This happens when trying a DNS search list, as in kubernetes, and breaks
	// even whitelisted DNS names.
	FQDNProxyDenyWithNameError = "nameError"

	// FQDNProxyDenyWithRefused is the response code for Domain refused. It is
	// the default for denied DNS requests.
	FQDNProxyDenyWithRefused = "refused"

	// FQDNProxyResponseMaxDelay is the maximum time the proxy holds back a response
	FQDNProxyResponseMaxDelay = "tofqdns-proxy-response-max-delay"

	// PreAllocateMapsName is the name of the option PreAllocateMaps
	PreAllocateMapsName = "preallocate-bpf-maps"

	// EnableAutoDirectRoutingName is the name for the EnableAutoDirectRouting option
	EnableAutoDirectRoutingName = "auto-direct-node-routes"

	// EnableIPSecName is the name of the option to enable IPSec
	EnableIPSecName = "enable-ipsec"

	// IPSecKeyFileName is the name of the option for ipsec key file
	IPSecKeyFileName = "ipsec-key-file"

	// KVstoreLeaseTTL is the time-to-live for lease in kvstore.
	KVstoreLeaseTTL = "kvstore-lease-ttl"

	// KVstorePeriodicSync is the time interval in which periodic
	// synchronization with the kvstore occurs
	KVstorePeriodicSync = "kvstore-periodic-sync"

	// KVstoreConnectivityTimeout is the timeout when performing kvstore operations
	KVstoreConnectivityTimeout = "kvstore-connectivity-timeout"

	// IPAllocationTimeout is the timeout when allocating CIDRs
	IPAllocationTimeout = "ip-allocation-timeout"

	// IdentityChangeGracePeriod is the name of the
	// IdentityChangeGracePeriod option
	IdentityChangeGracePeriod = "identity-change-grace-period"

	// EnableHealthChecking is the name of the EnableHealthChecking option
	EnableHealthChecking = "enable-health-checking"

	// EnableEndpointHealthChecking is the name of the EnableEndpointHealthChecking option
	EnableEndpointHealthChecking = "enable-endpoint-health-checking"

	// PolicyQueueSize is the size of the queues utilized by the policy
	// repository.
	PolicyQueueSize = "policy-queue-size"

	// EndpointQueueSize is the size of the EventQueue per-endpoint.
	EndpointQueueSize = "endpoint-queue-size"

	// SelectiveRegeneration specifies whether only the endpoints which policy
	// changes select should be regenerated upon policy changes.
	SelectiveRegeneration = "enable-selective-regeneration"

	// K8sEventHandover is the name of the K8sEventHandover option
	K8sEventHandover = "enable-k8s-event-handover"

	// Metrics represents the metrics subsystem that Cilium should expose
	// to prometheus.
	Metrics = "metrics"

	// LoopbackIPv4 is the address to use for service loopback SNAT
	LoopbackIPv4 = "ipv4-service-loopback-address"

	// EndpointInterfaceNamePrefix is the prefix name of the interface
	// names shared by all endpoints
	EndpointInterfaceNamePrefix = "endpoint-interface-name-prefix"

	// BlacklistConflictingRoutes removes all IPs from the IPAM block if a
	// local route not owned by Cilium conflicts with it
	BlacklistConflictingRoutes = "blacklist-conflicting-routes"

	// ForceLocalPolicyEvalAtSource forces a policy decision at the source
	// endpoint for all local communication
	ForceLocalPolicyEvalAtSource = "force-local-policy-eval-at-source"

	// SkipCRDCreation specifies whether the CustomResourceDefinition will be
	// created by the daemon
	SkipCRDCreation = "skip-crd-creation"

	// EnableEndpointRoutes enables use of per endpoint routes
	EnableEndpointRoutes = "enable-endpoint-routes"

	// ExcludeLocalAddress excludes certain addresses to be recognized as a
	// local address
	ExcludeLocalAddress = "exclude-local-address"

	// IPv4PodSubnets A list of IPv4 subnets that pods may be
	// assigned from. Used with CNI chaining where IPs are not directly managed
	// by Cilium.
	IPv4PodSubnets = "ipv4-pod-subnets"

	// IPv6PodSubnets A list of IPv6 subnets that pods may be
	// assigned from. Used with CNI chaining where IPs are not directly managed
	// by Cilium.
	IPv6PodSubnets = "ipv6-pod-subnets"

	// IPAM is the IPAM method to use
	IPAM = "ipam"

	// IPAMCRD is the value to select the CRD-backed IPAM plugin for
	// option.IPAM
	IPAMCRD = "crd"

	// IPAMENI is the value to select the AWS ENI IPAM plugin for option.IPAM
	IPAMENI = "eni"

	// AWSClientQPSLimit is the queries per second limit for the AWS client used by AWS ENI IPAM
	AWSClientQPSLimit = "aws-client-qps"

	// AWSClientBurst is the burst value allowed for the AWS client used by the AWS ENI IPAM
	AWSClientBurst = "aws-client-burst"

	// ENITags are the tags that will be added to every ENI created by the AWS ENI IPAM
	ENITags = "eni-tags"

	// UpdateEC2AdapterLimitViaAPI configures the operator to use the EC2 API to fill out the instnacetype to adapter limit mapping
	UpdateEC2AdapterLimitViaAPI = "update-ec2-apdater-limit-via-api"

	// K8sClientQPSLimit is the queries per second limit for the K8s client. Defaults to k8s client defaults.
	K8sClientQPSLimit = "k8s-client-qps"

	// K8sClientBurst is the burst value allowed for the K8s client. Defaults to k8s client defaults.
	K8sClientBurst = "k8s-client-burst"

	// AutoCreateCiliumNodeResource enables automatic creation of a
	// CiliumNode resource for the local node
	AutoCreateCiliumNodeResource = "auto-create-cilium-node-resource"

	// IPv4NativeRoutingCIDR describes a CIDR in which pod IPs are routable
	IPv4NativeRoutingCIDR = "native-routing-cidr"

	// EgressMasqueradeInterfaces is the selector used to select interfaces
	// subject to egress masquerading
	EgressMasqueradeInterfaces = "egress-masquerade-interfaces"

	// PolicyTriggerInterval is the amount of time between triggers of policy
	// updates are invoked.
	PolicyTriggerInterval = "policy-trigger-interval"

	// IdentityAllocationMode specifies what mode to use for identity
	// allocation
	IdentityAllocationMode = "identity-allocation-mode"

	// IdentityAllocationModeKVstore enables use of a key-value store such
	// as etcd or consul for identity allocation
	IdentityAllocationModeKVstore = "kvstore"

	// IdentityAllocationModeCRD enables use of Kubernetes CRDs for
	// identity allocation
	IdentityAllocationModeCRD = "crd"

	// DisableCNPStatusUpdates disables updating of CNP NodeStatus in the CNP
	// CRD.
	DisableCNPStatusUpdates = "disable-cnp-status-updates"

	// EnableLocalNodeRoute controls installation of the route which points
	// the allocation prefix of the local node.
	EnableLocalNodeRoute = "enable-local-node-route"

	// EnableWellKnownIdentities enables the use of well-known identities.
	// This is requires if identiy resolution is required to bring up the
	// control plane, e.g. when using the managed etcd feature
	EnableWellKnownIdentities = "enable-well-known-identities"

	// EnableRemoteNodeIdentity enables use of the remote-node identity
	EnableRemoteNodeIdentity = "enable-remote-node-identity"

	// EnableIPv4FragmentsTrackingName is the name of the option to enable
	// IPv4 fragments tracking for L4-based lookups
	EnableIPv4FragmentsTrackingName = "enable-ipv4-fragments-tracking"
)

// Default string arguments
var (
	FQDNRejectOptions = []string{FQDNProxyDenyWithNameError, FQDNProxyDenyWithRefused}

	// ContainerRuntimeAuto is the configuration for autodetecting the
	// container runtime backends that Cilium should use.
	ContainerRuntimeAuto = []string{"auto"}

	// MonitorAggregationFlagsDefault ensure that all TCP flags trigger
	// monitor notifications even under medium monitor aggregation.
	MonitorAggregationFlagsDefault = []string{"syn", "fin", "rst"}
)

// Available option for DaemonConfig.DatapathMode
const (
	// DatapathModeVeth specifies veth datapath mode (i.e. containers are
	// attached to a network via veth pairs)
	DatapathModeVeth = "veth"

	// DatapathModeIpvlan specifies ipvlan datapath mode
	DatapathModeIpvlan = "ipvlan"
)

// Available option for DaemonConfig.Tunnel
const (
	// TunnelVXLAN specifies VXLAN encapsulation
	TunnelVXLAN = "vxlan"

	// TunnelGeneve specifies Geneve encapsulation
	TunnelGeneve = "geneve"

	// TunnelDisabled specifies to disable encapsulation
	TunnelDisabled = "disabled"
)

// Available option for DaemonConfig.Ipvlan.OperationMode
const (
	// OperationModeL3S will respect iptables rules e.g. set up for masquerading
	OperationModeL3S = "L3S"

	// OperationModeL3 will bypass iptables rules on the host
	OperationModeL3 = "L3"
)

// Envoy option names
const (
	// HTTP403Message specifies the response body for 403 responses, defaults to "Access denied"
	HTTP403Message = "http-403-msg"

	// HTTPRequestTimeout specifies the time in seconds after which forwarded requests time out
	HTTPRequestTimeout = "http-request-timeout"

	// HTTPIdleTimeout spcifies the time in seconds if http stream being idle after which the
	// request times out
	HTTPIdleTimeout = "http-idle-timeout"

	// HTTPMaxGRPCTimeout specifies the maximum time in seconds that limits the values of
	// "grpc-timeout" headers being honored.
	HTTPMaxGRPCTimeout = "http-max-grpc-timeout"

	// HTTPRetryCount specifies the number of retries performed after a forwarded request fails
	HTTPRetryCount = "http-retry-count"

	// HTTPRetryTimeout is the time in seconds before an uncompleted request is retried.
	HTTPRetryTimeout = "http-retry-timeout"

	// ProxyConnectTimeout specifies the time in seconds after which a TCP connection attempt
	// is considered timed out
	ProxyConnectTimeout = "proxy-connect-timeout"

	// ReadCNIConfiguration reads the CNI configuration file and extracts
	// Cilium relevant information. This can be used to pass per node
	// configuration to Cilium.
	ReadCNIConfiguration = "read-cni-conf"

	// WriteCNIConfigurationWhenReady writes the CNI configuration to the
	// specified location once the agent is ready to serve requests. This
	// allows to keep a Kubernetes node NotReady until Cilium is up and
	// running and able to schedule endpoints.
	WriteCNIConfigurationWhenReady = "write-cni-conf-when-ready"
)

const (
	// NodePortMinDefault is the minimal port to listen for NodePort requests
	NodePortMinDefault = 30000

	// NodePortMaxDefault is the maximum port to listen for NodePort requests
	NodePortMaxDefault = 32767

	// KubeProxyReplacementProbe specifies to auto-enable available features for
	// kube-proxy replacement
	KubeProxyReplacementProbe = "probe"

	// KubeProxyReplacementPartial specifies to enable only selected kube-proxy
	// replacement features (might panic)
	KubeProxyReplacementPartial = "partial"

	// KubeProxyReplacementStrict specifies to enable all kube-proxy replacement
	// features (might panic)
	KubeProxyReplacementStrict = "strict"

	// KubeProxyReplacementDisabled specified to completely disable kube-proxy
	// replacement
	KubeProxyReplacementDisabled = "disabled"
)

// GetTunnelModes returns the list of all tunnel modes
func GetTunnelModes() string {
	return fmt.Sprintf("%s, %s, %s", TunnelVXLAN, TunnelGeneve, TunnelDisabled)
}

// getEnvName returns the environment variable to be used for the given option name.
func getEnvName(option string) string {
	under := strings.Replace(option, "-", "_", -1)
	upper := strings.ToUpper(under)
	return ciliumEnvPrefix + upper
}

// RegisteredOptions maps all options that are bind to viper.
var RegisteredOptions = map[string]struct{}{}

// BindEnv binds the option name with an deterministic generated environment
// variable which s based on the given optName. If the same optName is bind
// more than 1 time, this function panics.
func BindEnv(optName string) {
	registerOpt(optName)
	viper.BindEnv(optName, getEnvName(optName))
}

// BindEnvWithLegacyEnvFallback binds the given option name with either the same
// environment variable as BindEnv, if it's set, or with the given legacyEnvName.
//
// The function is used to work around the viper.BindEnv limitation that only
// one environment variable can be bound for an option, and we need multiple
// environment variables due to backward compatibility reasons.
func BindEnvWithLegacyEnvFallback(optName, legacyEnvName string) {
	registerOpt(optName)

	envName := getEnvName(optName)
	if os.Getenv(envName) == "" {
		envName = legacyEnvName
	}

	viper.BindEnv(optName, envName)
}

func registerOpt(optName string) {
	_, ok := RegisteredOptions[optName]
	if ok || optName == "" {
		panic(fmt.Errorf("option already registered: %s", optName))
	}
	RegisteredOptions[optName] = struct{}{}
}

// LogRegisteredOptions logs all options that where bind to viper.
func LogRegisteredOptions(entry *logrus.Entry) {
	keys := make([]string, 0, len(RegisteredOptions))
	for k := range RegisteredOptions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		entry.Infof("  --%s='%s'", k, viper.GetString(k))
	}
}

// IpvlanConfig is the configuration used by Daemon when in ipvlan mode.
type IpvlanConfig struct {
	MasterDeviceIndex int
	OperationMode     string
}

// DaemonConfig is the configuration used by Daemon.
type DaemonConfig struct {
	BpfDir           string     // BPF template files directory
	LibDir           string     // Cilium library files directory
	RunDir           string     // Cilium runtime directory
	NAT46Prefix      *net.IPNet // NAT46 IPv6 Prefix
	Device           string     // Receive device
	DevicePreFilter  string     // XDP device
	ModePreFilter    string     // XDP mode, values: { native | generic }
	HostV4Addr       net.IP     // Host v4 address of the snooping device
	HostV6Addr       net.IP     // Host v6 address of the snooping device
	EncryptInterface string     // Set with name of network facing interface to encrypt
	EncryptNode      bool       // Set to true for encrypting node IP traffic

	Ipvlan IpvlanConfig // Ipvlan related configuration

	DatapathMode string // Datapath mode
	Tunnel       string // Tunnel mode

	DryMode bool // Do not create BPF maps, devices, ..

	// RestoreState enables restoring the state from previous running daemons.
	RestoreState bool

	// EnableHostIPRestore enables restoring the host IPs based on state
	// left behind by previous Cilium runs.
	EnableHostIPRestore bool

	KeepConfig    bool // Keep configuration of existing endpoints when starting up.
	KeepTemplates bool // Do not overwrite the template files

	// AllowLocalhost defines when to allows the local stack to local endpoints
	// values: { auto | always | policy }
	AllowLocalhost string

	// StateDir is the directory where runtime state of endpoints is stored
	StateDir string

	// Options changeable at runtime
	Opts *IntOptions

	// Mutex for serializing configuration updates to the daemon.
	ConfigPatchMutex lock.RWMutex

	// Monitor contains the configuration for the node monitor.
	Monitor *models.MonitorStatus

	// AccessLog is the path to the access log of supported L7 requests observed.
	AccessLog string

	// AgentLabels contains additional labels to identify this agent in monitor events.
	AgentLabels []string

	// IPv6ClusterAllocCIDR is the base CIDR used to allocate IPv6 node
	// CIDRs if allocation is not performed by an orchestration system
	IPv6ClusterAllocCIDR string

	// IPv6ClusterAllocCIDRBase is derived from IPv6ClusterAllocCIDR and
	// contains the CIDR without the mask, e.g. "fdfd::1/64" -> "fdfd::"
	//
	// This variable should never be written to, it is initialized via
	// DaemonConfig.Validate()
	IPv6ClusterAllocCIDRBase string

	// K8sRequireIPv4PodCIDR requires the k8s node resource to specify the
	// IPv4 PodCIDR. Cilium will block bootstrapping until the information
	// is available.
	K8sRequireIPv4PodCIDR bool

	// K8sRequireIPv6PodCIDR requires the k8s node resource to specify the
	// IPv6 PodCIDR. Cilium will block bootstrapping until the information
	// is available.
	K8sRequireIPv6PodCIDR bool

	// K8sServiceCacheSize is the service cache size for cilium k8s package.
	K8sServiceCacheSize uint

	// K8sForceJSONPatch when set, uses JSON Patch to update CNP and CEP
	// status in kube-apiserver.
	K8sForceJSONPatch bool

	// K8sWatcherQueueSize is the queue size used to serialize each k8s event
	// type.
	K8sWatcherQueueSize uint

	// MTU is the maximum transmission unit of the underlying network
	MTU int

	// ClusterName is the name of the cluster
	ClusterName string

	// ClusterID is the unique identifier of the cluster
	ClusterID int

	// ClusterMeshConfig is the path to the clustermesh configuration directory
	ClusterMeshConfig string

	// CTMapEntriesGlobalTCP is the maximum number of conntrack entries
	// allowed in each TCP CT table for IPv4/IPv6.
	CTMapEntriesGlobalTCP int

	// CTMapEntriesGlobalAny is the maximum number of conntrack entries
	// allowed in each non-TCP CT table for IPv4/IPv6.
	CTMapEntriesGlobalAny int

	// CTMapEntriesTimeout* values configured by the user.
	CTMapEntriesTimeoutTCP    time.Duration
	CTMapEntriesTimeoutAny    time.Duration
	CTMapEntriesTimeoutSVCTCP time.Duration
	CTMapEntriesTimeoutSVCAny time.Duration
	CTMapEntriesTimeoutSYN    time.Duration
	CTMapEntriesTimeoutFIN    time.Duration

	// MonitorAggregationInterval configures the interval between monitor
	// messages when monitor aggregation is enabled.
	MonitorAggregationInterval time.Duration

	// MonitorAggregationFlags determines which TCP flags that the monitor
	// aggregation ensures reports are generated for when monitor-aggragation
	// is enabled. Network byte-order.
	MonitorAggregationFlags uint16

	// NATMapEntriesGlobal is the maximum number of NAT mappings allowed
	// in the BPF NAT table
	NATMapEntriesGlobal int

	// PolicyMapMaxEntries is the maximum number of peer identities that an
	// endpoint may allow traffic to exchange traffic with.
	PolicyMapMaxEntries int

	// DisableCiliumEndpointCRD disables the use of CiliumEndpoint CRD
	DisableCiliumEndpointCRD bool

	// MaxControllerInterval is the maximum value for a controller's
	// RunInterval. Zero means unlimited.
	MaxControllerInterval int

	// UseSingleClusterRoute specifies whether to use a single cluster route
	// instead of per-node routes.
	UseSingleClusterRoute bool

	// HTTP403Message is the error message to return when a HTTP 403 is returned
	// by the proxy, if L7 policy is configured.
	HTTP403Message string

	// HTTPRequestTimeout is the time in seconds after which Envoy responds with an
	// error code on a request that has not yet completed. This needs to be longer
	// than the HTTPIdleTimeout
	HTTPRequestTimeout int

	// HTTPIdleTimeout is the time in seconds of a HTTP stream having no traffic after
	// which Envoy responds with an error code. This needs to be shorter than the
	// HTTPRequestTimeout
	HTTPIdleTimeout int

	// HTTPMaxGRPCTimeout is the upper limit to which "grpc-timeout" headers in GRPC
	// requests are honored by Envoy. If 0 there is no limit. GRPC requests are not
	// bound by the HTTPRequestTimeout, but ARE affected by the idle timeout!
	HTTPMaxGRPCTimeout int

	// HTTPRetryCount is the upper limit on how many times Envoy retries failed requests.
	HTTPRetryCount int

	// HTTPRetryTimeout is the time in seconds before an uncompleted request is retried.
	HTTPRetryTimeout int

	// ProxyConnectTimeout is the time in seconds after which Envoy considers a TCP
	// connection attempt to have timed out.
	ProxyConnectTimeout int

	// BPFCompilationDebug specifies whether to compile BPF programs compilation
	// debugging enabled.
	BPFCompilationDebug bool

	// EnvoyLogPath specifies where to store the Envoy proxy logs when Envoy
	// runs in the same container as Cilium.
	EnvoyLogPath string

	// EnableSockOps specifies whether to enable sockops (socket lookup).
	SockopsEnable bool

	// PrependIptablesChains is the name of the option to enable prepending
	// iptables chains instead of appending
	PrependIptablesChains bool

	// K8sNamespace is the name of the namespace in which Cilium is
	// deployed in when running in Kubernetes mode
	K8sNamespace string

	// EnableIPv4 is true when IPv4 is enabled
	EnableIPv4 bool

	// EnableIPv6 is true when IPv6 is enabled
	EnableIPv6 bool

	// EnableL7Proxy is the option to enable L7 proxy
	EnableL7Proxy bool

	// EnableIPSec is true when IPSec is enabled
	EnableIPSec bool

	// IPSec key file for stored keys
	IPSecKeyFile string

	// MonitorQueueSize is the size of the monitor event queue
	MonitorQueueSize int

	// CLI options

	BPFRoot                       string
	CGroupRoot                    string
	BPFCompileDebug               string
	ConfigFile                    string
	ConfigDir                     string
	Debug                         bool
	DebugVerbose                  []string
	DisableConntrack              bool
	DisableK8sServices            bool
	EnableHostReachableServices   bool
	EnableHostServicesTCP         bool
	EnableHostServicesUDP         bool
	DockerEndpoint                string
	EnablePolicy                  string
	EnableTracing                 bool
	EnvoyLog                      string
	DisableEnvoyVersionCheck      bool
	FixedIdentityMapping          map[string]string
	FixedIdentityMappingValidator func(val string) (string, error)
	IPv4Range                     string
	IPv6Range                     string
	IPv4ServiceRange              string
	IPv6ServiceRange              string
	K8sAPIServer                  string
	K8sKubeConfigPath             string
	K8sWatcherEndpointSelector    string
	KVStore                       string
	KVStoreOpt                    map[string]string
	LabelPrefixFile               string
	Labels                        []string
	LogDriver                     []string
	LogOpt                        map[string]string
	Logstash                      bool
	LogSystemLoadConfig           bool
	NAT46Range                    string

	// Masquerade specifies whether or not to masquerade packets from endpoints
	// leaving the host.
	Masquerade             bool
	InstallIptRules        bool
	MonitorAggregation     string
	PreAllocateMaps        bool
	IPv6NodeAddr           string
	IPv4NodeAddr           string
	SidecarHTTPProxy       bool
	SidecarIstioProxyImage string
	SocketPath             string
	TracePayloadlen        int
	Version                string
	PProf                  bool
	PrometheusServeAddr    string
	ToFQDNsMinTTL          int

	// ToFQDNsProxyPort is the user-configured global, shared, DNS listen port used
	// by the DNS Proxy. Both UDP and TCP are handled on the same port. When it
	// is 0 a random port will be assigned, and can be obtained from
	// DefaultDNSProxy below.
	ToFQDNsProxyPort int

	// ToFQDNsEnablePoller enables the DNS poller that polls toFQDNs.matchName
	ToFQDNsEnablePoller bool

	// ToFQDNsEnablePollerEvents controls sending a monitor event for each DNS
	// response the DNS poller sees
	ToFQDNsEnablePollerEvents bool

	// ToFQDNsMaxIPsPerHost defines the maximum number of IPs to maintain
	// for each FQDN name in an endpoint's FQDN cache
	ToFQDNsMaxIPsPerHost int

	// ToFQDNsMaxIPsPerHost defines the maximum number of IPs to retain for
	// expired DNS lookups with still-active connections
	ToFQDNsMaxDeferredConnectionDeletes int

	// FQDNRejectResponse is the dns-proxy response for invalid dns-proxy request
	FQDNRejectResponse string

	// FQDNProxyResponseMaxDelay The maximum time the DNS proxy holds an allowed
	// DNS response before sending it along. Responses are sent as soon as the
	// datapath is updated with the new IP information.
	FQDNProxyResponseMaxDelay time.Duration

	// Path to a file with DNS cache data to preload on startup
	ToFQDNsPreCache string

	// HostDevice will be device used by Cilium to connect to the outside world.
	HostDevice string

	// FlannelMasterDevice installs a BPF program in the given interface
	// to allow for policy enforcement mode on top of flannel.
	FlannelMasterDevice string

	// FlannelUninstallOnExit removes the BPF programs that were installed by
	// Cilium on all interfaces created by the flannel.
	FlannelUninstallOnExit bool

	// EnableAutoDirectRouting enables installation of direct routes to
	// other nodes when available
	EnableAutoDirectRouting bool

	// EnableLocalNodeRoute controls installation of the route which points
	// the allocation prefix of the local node.
	EnableLocalNodeRoute bool

	// EnableHealthChecking enables health checking between nodes and
	// health endpoints
	EnableHealthChecking bool

	// EnableEndpointHealthChecking enables health checking between virtual
	// health endpoints
	EnableEndpointHealthChecking bool

	// KVstoreKeepAliveInterval is the interval in which the lease is being
	// renewed. This must be set to a value lesser than the LeaseTTL ideally
	// by a factor of 3.
	KVstoreKeepAliveInterval time.Duration

	// KVstoreLeaseTTL is the time-to-live for kvstore lease.
	KVstoreLeaseTTL time.Duration

	// KVstorePeriodicSync is the time interval in which periodic
	// synchronization with the kvstore occurs
	KVstorePeriodicSync time.Duration

	// KVstoreConnectivityTimeout is the timeout when performing kvstore operations
	KVstoreConnectivityTimeout time.Duration

	// IPAllocationTimeout is the timeout when allocating CIDRs
	IPAllocationTimeout time.Duration

	// IdentityChangeGracePeriod is the grace period that needs to pass
	// before an endpoint that has changed its identity will start using
	// that new identity. During the grace period, the new identity has
	// already been allocated and other nodes in the cluster have a chance
	// to whitelist the new upcoming identity of the endpoint.
	IdentityChangeGracePeriod time.Duration

	// PolicyQueueSize is the size of the queues for the policy repository.
	// A larger queue means that more events related to policy can be buffered.
	PolicyQueueSize int

	// EndpointQueueSize is the size of the EventQueue per-endpoint. A larger
	// queue means that more events can be buffered per-endpoint. This is useful
	// in the case where a cluster might be under high load for endpoint-related
	// events, specifically those which cause many regenerations.
	EndpointQueueSize int

	// SelectiveRegeneration, when true, enables the functionality to only
	// regenerate endpoints which are selected by the policy rules that have
	// been changed (added, deleted, or updated). If false, then all endpoints
	// are regenerated upon every policy change regardless of the scope of the
	// policy change.
	SelectiveRegeneration bool

	// ConntrackGCInterval is the connection tracking garbage collection
	// interval
	ConntrackGCInterval time.Duration

	// K8sEventHandover enables use of the kvstore to optimize Kubernetes
	// event handling by listening for k8s events in the operator and
	// mirroring it into the kvstore for reduced overhead in large
	// clusters.
	K8sEventHandover bool

	// MetricsConfig is the configuration set in metrics
	MetricsConfig metrics.Configuration

	// LoopbackIPv4 is the address to use for service loopback SNAT
	LoopbackIPv4 string

	// EndpointInterfaceNamePrefix is the prefix name of the interface
	// names shared by all endpoints
	EndpointInterfaceNamePrefix string

	// BlacklistConflictingRoutes removes all IPs from the IPAM block if a
	// local route not owned by Cilium conflicts with it
	BlacklistConflictingRoutes bool

	// ForceLocalPolicyEvalAtSource forces a policy decision at the source
	// endpoint for all local communication
	ForceLocalPolicyEvalAtSource bool

	// SkipCRDCreation disables creation of the CustomResourceDefinition
	// on daemon startup
	SkipCRDCreation bool

	// EnableEndpointRoutes enables use of per endpoint routes
	EnableEndpointRoutes bool

	// Specifies wheather to annotate the kubernetes nodes or not
	AnnotateK8sNode bool

	// RunMonitorAgent indicates whether to run the monitor agent
	RunMonitorAgent bool

	// ReadCNIConfiguration reads the CNI configuration file and extracts
	// Cilium relevant information. This can be used to pass per node
	// configuration to Cilium.
	ReadCNIConfiguration string

	// WriteCNIConfigurationWhenReady writes the CNI configuration to the
	// specified location once the agent is ready to serve requests. This
	// allows to keep a Kubernetes node NotReady until Cilium is up and
	// running and able to schedule endpoints.
	WriteCNIConfigurationWhenReady string

	// EnableNodePort enables k8s NodePort service implementation in BPF
	EnableNodePort bool

	// NodePortMode indicates in which mode NodePort implementation should run
	// ("snat" or "dsr")
	NodePortMode string

	// KubeProxyReplacement controls how to enable kube-proxy replacement
	// features in BPF datapath
	KubeProxyReplacement string

	// EnableExternalIPs enables implementation of k8s services with externalIPs in datapath
	EnableExternalIPs bool

	// K8sEnableEndpointSlice enables k8s endpoint slice feature that is used
	// in kubernetes.
	K8sEnableK8sEndpointSlice bool

	// NodePortMin is the minimum port address for the NodePort range
	NodePortMin int

	// NodePortMax is the maximum port address for the NodePort range
	NodePortMax int

	// excludeLocalAddresses excludes certain addresses to be recognized as
	// a local address
	excludeLocalAddresses []*net.IPNet

	// IPv4PodSubnets available subnets to be assign IPv4 addresses to pods from
	IPv4PodSubnets []*net.IPNet

	// IPv6PodSubnets available subnets to be assign IPv6 addresses to pods from
	IPv6PodSubnets []*net.IPNet

	// IPAM is the IPAM method to use
	IPAM string

	// AutoCreateCiliumNodeResource enables automatic creation of a
	// CiliumNode resource for the local node
	AutoCreateCiliumNodeResource bool

	// ipv4NativeRoutingCIDR describes a CIDR in which pod IPs are routable
	ipv4NativeRoutingCIDR *cidr.CIDR

	// EgressMasqueradeInterfaces is the selector used to select interfaces
	// subject to egress masquerading
	EgressMasqueradeInterfaces string

	// PolicyTriggerInterval is the amount of time between when policy updates
	// are triggered.
	PolicyTriggerInterval time.Duration

	// IdentityAllocationMode specifies what mode to use for identity
	// allocation
	IdentityAllocationMode string

	// DisableCNPStatusUpdates disables updating of CNP NodeStatus in the CNP
	// CRD.
	DisableCNPStatusUpdates bool

	// AllowICMPFragNeeded allows ICMP Fragmentation Needed type packets in
	// the network policy for cilium-agent.
	AllowICMPFragNeeded bool

	// AwsInstanceLimitMapping allows overwirting AWS instance limits defined in
	// pkg/aws/eni/limits.go
	// e.g. {"a1.medium": "2,4,4", "a2.custom2": "4,5,6"}
	AwsInstanceLimitMapping map[string]string

	// AwsReleaseExcessIps allows releasing excess free IP addresses from ENI.
	// Enabling this option reduces waste of IP addresses but may increase
	// the number of API calls to AWS EC2 service.
	AwsReleaseExcessIps bool

	// EnableWellKnownIdentities enables the use of well-known identities.
	// This is requires if identiy resolution is required to bring up the
	// control plane, e.g. when using the managed etcd feature
	EnableWellKnownIdentities bool

	// CertsDirectory is the root directory to be used by cilium to find
	// certificates locally.
	CertDirectory string

	// EnableRemoteNodeIdentity enables use of the remote-node identity
	EnableRemoteNodeIdentity bool

	// EnableIPv4FragmentsTracking enables IPv4 fragments tracking for
	// L4-based lookups
	EnableIPv4FragmentsTracking bool
}

var (
	// Config represents the daemon configuration
	Config = &DaemonConfig{
		Opts:                         NewIntOptions(&DaemonOptionLibrary),
		Monitor:                      &models.MonitorStatus{Cpus: int64(runtime.NumCPU()), Npages: 64, Pagesize: int64(os.Getpagesize()), Lost: 0, Unknown: 0},
		IPv6ClusterAllocCIDR:         defaults.IPv6ClusterAllocCIDR,
		IPv6ClusterAllocCIDRBase:     defaults.IPv6ClusterAllocCIDRBase,
		EnableHostIPRestore:          defaults.EnableHostIPRestore,
		EnableHealthChecking:         defaults.EnableHealthChecking,
		EnableEndpointHealthChecking: defaults.EnableEndpointHealthChecking,
		EnableIPv4:                   defaults.EnableIPv4,
		EnableIPv6:                   defaults.EnableIPv6,
		EnableL7Proxy:                defaults.EnableL7Proxy,
		ToFQDNsMaxIPsPerHost:         defaults.ToFQDNsMaxIPsPerHost,
		KVstorePeriodicSync:          defaults.KVstorePeriodicSync,
		KVstoreConnectivityTimeout:   defaults.KVstoreConnectivityTimeout,
		IPAllocationTimeout:          defaults.IPAllocationTimeout,
		IdentityChangeGracePeriod:    defaults.IdentityChangeGracePeriod,
		FixedIdentityMapping:         make(map[string]string),
		KVStoreOpt:                   make(map[string]string),
		LogOpt:                       make(map[string]string),
		SelectiveRegeneration:        defaults.SelectiveRegeneration,
		LoopbackIPv4:                 defaults.LoopbackIPv4,
		EndpointInterfaceNamePrefix:  defaults.EndpointInterfaceNamePrefix,
		BlacklistConflictingRoutes:   defaults.BlacklistConflictingRoutes,
		ForceLocalPolicyEvalAtSource: defaults.ForceLocalPolicyEvalAtSource,
		EnableEndpointRoutes:         defaults.EnableEndpointRoutes,
		AnnotateK8sNode:              defaults.AnnotateK8sNode,
		K8sServiceCacheSize:          defaults.K8sServiceCacheSize,
		AutoCreateCiliumNodeResource: defaults.AutoCreateCiliumNodeResource,
		IdentityAllocationMode:       IdentityAllocationModeKVstore,
		AllowICMPFragNeeded:          defaults.AllowICMPFragNeeded,
		EnableWellKnownIdentities:    defaults.EnableEndpointRoutes,
		K8sEnableK8sEndpointSlice:    defaults.K8sEnableEndpointSlice,
	}
)

// IPv4NativeRoutingCIDR returns the native routing CIDR if configured
func (c *DaemonConfig) IPv4NativeRoutingCIDR() (cidr *cidr.CIDR) {
	c.ConfigPatchMutex.RLock()
	cidr = c.ipv4NativeRoutingCIDR
	c.ConfigPatchMutex.RUnlock()
	return
}

// SetIPv4NativeRoutingCIDR sets the native routing CIDR
func (c *DaemonConfig) SetIPv4NativeRoutingCIDR(cidr *cidr.CIDR) {
	c.ConfigPatchMutex.Lock()
	c.ipv4NativeRoutingCIDR = cidr
	c.ConfigPatchMutex.Unlock()
}

// IsExcludedLocalAddress returns true if the specified IP matches one of the
// excluded local IP ranges
func (c *DaemonConfig) IsExcludedLocalAddress(ip net.IP) bool {
	for _, ipnet := range c.excludeLocalAddresses {
		if ipnet.Contains(ip) {
			return true
		}
	}

	return false
}

// IsPodSubnetsDefined returns true if encryption subnets should be configured at init time.
func (c *DaemonConfig) IsPodSubnetsDefined() bool {
	return len(c.IPv4PodSubnets) > 0 || len(c.IPv6PodSubnets) > 0
}

// GetNodeConfigPath returns the full path of the NodeConfigFile.
func (c *DaemonConfig) GetNodeConfigPath() string {
	return filepath.Join(c.GetGlobalsDir(), common.NodeConfigFile)
}

// GetGlobalsDir returns the path for the globals directory.
func (c *DaemonConfig) GetGlobalsDir() string {
	return filepath.Join(c.StateDir, "globals")
}

// AlwaysAllowLocalhost returns true if the daemon has the option set that
// localhost can always reach local endpoints
func (c *DaemonConfig) AlwaysAllowLocalhost() bool {
	switch c.AllowLocalhost {
	case AllowLocalhostAlways:
		return true
	case AllowLocalhostAuto, AllowLocalhostPolicy:
		return false
	default:
		return false
	}
}

// TracingEnabled returns if tracing policy (outlining which rules apply to a
// specific set of labels) is enabled.
func (c *DaemonConfig) TracingEnabled() bool {
	return c.Opts.IsEnabled(PolicyTracing)
}

// IsFlannelMasterDeviceSet returns if the flannel master device is set.
func (c *DaemonConfig) IsFlannelMasterDeviceSet() bool {
	return len(c.FlannelMasterDevice) != 0
}

func (c *DaemonConfig) validateIPv6ClusterAllocCIDR() error {
	ip, cidr, err := net.ParseCIDR(c.IPv6ClusterAllocCIDR)
	if err != nil {
		return err
	}

	if cidr == nil {
		return fmt.Errorf("ParseCIDR returned nil")
	}

	if ones, _ := cidr.Mask.Size(); ones != 64 {
		return fmt.Errorf("CIDR length must be /64")
	}

	c.IPv6ClusterAllocCIDRBase = ip.Mask(cidr.Mask).String()

	return nil
}

// Validate validates the daemon configuration
func (c *DaemonConfig) Validate() error {
	if err := c.validateIPv6ClusterAllocCIDR(); err != nil {
		return fmt.Errorf("unable to parse CIDR value '%s' of option --%s: %s",
			c.IPv6ClusterAllocCIDR, IPv6ClusterAllocCIDRName, err)
	}

	if c.MTU < 0 {
		return fmt.Errorf("MTU '%d' cannot be negative", c.MTU)
	}

	if c.IPAM == IPAMENI && c.EnableIPv6 {
		return fmt.Errorf("IPv6 cannot be enabled in ENI IPAM mode")
	}

	switch c.Tunnel {
	case TunnelVXLAN, TunnelGeneve, "":
	case TunnelDisabled:
		if c.UseSingleClusterRoute {
			return fmt.Errorf("option --%s cannot be used in combination with --%s=%s",
				SingleClusterRouteName, TunnelName, TunnelDisabled)
		}
	default:
		return fmt.Errorf("invalid tunnel mode '%s', valid modes = {%s}", c.Tunnel, GetTunnelModes())
	}

	if c.ClusterID < ClusterIDMin || c.ClusterID > ClusterIDMax {
		return fmt.Errorf("invalid cluster id %d: must be in range %d..%d",
			c.ClusterID, ClusterIDMin, ClusterIDMax)
	}

	if c.ClusterID != 0 {
		if c.ClusterName == defaults.ClusterName {
			return fmt.Errorf("cannot use default cluster name (%s) with option %s",
				defaults.ClusterName, ClusterIDName)
		}
	}

	if c.CTMapEntriesGlobalTCP < LimitTableMin || c.CTMapEntriesGlobalAny < LimitTableMin {
		return fmt.Errorf("specified CT tables values %d/%d must exceed minimum %d",
			c.CTMapEntriesGlobalTCP, c.CTMapEntriesGlobalAny, LimitTableMin)
	}
	if c.CTMapEntriesGlobalTCP > LimitTableMax || c.CTMapEntriesGlobalAny > LimitTableMax {
		return fmt.Errorf("specified CT tables values %d/%d must not exceed maximum %d",
			c.CTMapEntriesGlobalTCP, c.CTMapEntriesGlobalAny, LimitTableMax)
	}
	if c.NATMapEntriesGlobal < LimitTableMin {
		return fmt.Errorf("specified NAT table size %d must exceed minimum %d",
			c.NATMapEntriesGlobal, LimitTableMin)
	}
	if c.NATMapEntriesGlobal > LimitTableMax {
		return fmt.Errorf("specified NAT tables size %d must not exceed maximum %d",
			c.NATMapEntriesGlobal, LimitTableMax)
	}
	if c.NATMapEntriesGlobal > c.CTMapEntriesGlobalTCP+c.CTMapEntriesGlobalAny {
		if c.NATMapEntriesGlobal == NATMapEntriesGlobalDefault {
			// Auto-size for the case where CT table size was adapted but NAT still on default
			c.NATMapEntriesGlobal = int((c.CTMapEntriesGlobalTCP + c.CTMapEntriesGlobalAny) * 2 / 3)
		} else {
			return fmt.Errorf("specified NAT tables size %d must not exceed maximum CT table size %d",
				c.NATMapEntriesGlobal, c.CTMapEntriesGlobalTCP+c.CTMapEntriesGlobalAny)
		}
	}

	policyMapMin := (1 << 8)
	policyMapMax := (1 << 16)
	if c.PolicyMapMaxEntries < policyMapMin {
		return fmt.Errorf("specified PolicyMap max entries %d must exceed minimum %d",
			c.PolicyMapMaxEntries, policyMapMin)
	}
	if c.PolicyMapMaxEntries > policyMapMax {
		return fmt.Errorf("specified PolicyMap max entries %d must not exceed maximum %d",
			c.PolicyMapMaxEntries, policyMapMax)
	}
	// Validate that the KVStore Lease TTL value lies between a particular range.
	if c.KVstoreLeaseTTL > defaults.KVstoreLeaseMaxTTL || c.KVstoreLeaseTTL < defaults.LockLeaseTTL {
		return fmt.Errorf("KVstoreLeaseTTL does not lie in required range(%ds, %ds)",
			int64(defaults.LockLeaseTTL.Seconds()),
			int64(defaults.KVstoreLeaseMaxTTL.Seconds()))
	}

	if c.WriteCNIConfigurationWhenReady != "" && c.ReadCNIConfiguration == "" {
		return fmt.Errorf("%s must be set when using %s", ReadCNIConfiguration, WriteCNIConfigurationWhenReady)
	}

	if c.EnableHostReachableServices && !c.EnableHostServicesUDP && !c.EnableHostServicesTCP {
		return fmt.Errorf("%s must be at minimum one of [%s,%s]",
			HostReachableServicesProtos, HostServicesTCP, HostServicesUDP)
	}

	return nil
}

// ReadDirConfig reads the given directory and returns a map that maps the
// filename to the contents of that file.
func ReadDirConfig(dirName string) (map[string]interface{}, error) {
	m := map[string]interface{}{}
	fi, err := ioutil.ReadDir(dirName)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("unable to read configuration directory: %s", err)
	}
	for _, f := range fi {
		if f.Mode().IsDir() {
			continue
		}
		fName := filepath.Join(dirName, f.Name())

		// the file can still be a symlink to a directory
		if f.Mode()&os.ModeSymlink == 0 {
			absFileName, err := filepath.EvalSymlinks(fName)
			if err != nil {
				log.Warnf("Unable to read configuration file %q: %s", absFileName, err)
				continue
			}
			fName = absFileName
		}

		f, err = os.Stat(fName)
		if err != nil {
			log.Warnf("Unable to read configuration file %q: %s", fName, err)
			continue
		}
		if f.Mode().IsDir() {
			continue
		}

		b, err := ioutil.ReadFile(fName)
		if err != nil {
			log.Warnf("Unable to read configuration file %q: %s", fName, err)
			continue
		}
		m[f.Name()] = string(bytes.TrimSpace(b))
	}
	return m, nil
}

// MergeConfig merges the given configuration map with viper's configuration.
func MergeConfig(m map[string]interface{}) error {
	err := viper.MergeConfigMap(m)
	if err != nil {
		return fmt.Errorf("unable to read merge directory configuration: %s", err)
	}
	return nil
}

// ReplaceDeprecatedFields replaces the deprecated options set with the new set
// of options that overwrite the deprecated ones.
// This function replaces the deprecated fields used by environment variables
// with a different name than the option they are setting. This also replaces
// the deprecated names used in the Kubernetes ConfigMap.
// Once we remove them from this function we also need to remove them from
// daemon_main.go and warn users about the old environment variable nor the
// option in the configuration map have any effect.
func ReplaceDeprecatedFields(m map[string]interface{}) {
	deprecatedFields := map[string]string{
		"monitor-aggregation-level":   MonitorAggregationName,
		"ct-global-max-entries-tcp":   CTMapEntriesGlobalTCPName,
		"ct-global-max-entries-other": CTMapEntriesGlobalAnyName,
	}
	for deprecatedOption, newOption := range deprecatedFields {
		if deprecatedValue, ok := m[deprecatedOption]; ok {
			if _, ok := m[newOption]; !ok {
				m[newOption] = deprecatedValue
			}
		}
	}
}

func (c *DaemonConfig) parseExcludedLocalAddresses(s []string) error {
	for _, ipString := range s {
		_, ipnet, err := net.ParseCIDR(ipString)
		if err != nil {
			return fmt.Errorf("unable to parse excluded local address %s: %s", ipString, err)
		}

		c.excludeLocalAddresses = append(c.excludeLocalAddresses, ipnet)
	}

	return nil
}

// Populate sets all options with the values from viper
func (c *DaemonConfig) Populate() {
	var err error

	c.AccessLog = viper.GetString(AccessLog)
	c.AgentLabels = viper.GetStringSlice(AgentLabels)
	c.AllowICMPFragNeeded = viper.GetBool(AllowICMPFragNeeded)
	c.AllowLocalhost = viper.GetString(AllowLocalhost)
	c.AnnotateK8sNode = viper.GetBool(AnnotateK8sNode)
	c.AutoCreateCiliumNodeResource = viper.GetBool(AutoCreateCiliumNodeResource)
	c.BPFCompilationDebug = viper.GetBool(BPFCompileDebugName)
	c.CTMapEntriesGlobalTCP = viper.GetInt(CTMapEntriesGlobalTCPName)
	c.CTMapEntriesGlobalAny = viper.GetInt(CTMapEntriesGlobalAnyName)
	c.NATMapEntriesGlobal = viper.GetInt(NATMapEntriesGlobalName)
	c.BPFRoot = viper.GetString(BPFRoot)
	c.CertDirectory = viper.GetString(CertsDirectory)
	c.CGroupRoot = viper.GetString(CGroupRoot)
	c.ClusterID = viper.GetInt(ClusterIDName)
	c.ClusterName = viper.GetString(ClusterName)
	c.ClusterMeshConfig = viper.GetString(ClusterMeshConfigName)
	c.DatapathMode = viper.GetString(DatapathMode)
	c.Debug = viper.GetBool(DebugArg)
	c.DebugVerbose = viper.GetStringSlice(DebugVerbose)
	c.Device = viper.GetString(Device)
	c.DisableConntrack = viper.GetBool(DisableConntrack)
	c.EnableIPv4 = getIPv4Enabled()
	c.EnableIPv6 = viper.GetBool(EnableIPv6Name)
	c.EnableIPSec = viper.GetBool(EnableIPSecName)
	c.EnableWellKnownIdentities = viper.GetBool(EnableWellKnownIdentities)
	c.EndpointInterfaceNamePrefix = viper.GetString(EndpointInterfaceNamePrefix)
	c.DevicePreFilter = viper.GetString(PrefilterDevice)
	c.DisableCiliumEndpointCRD = viper.GetBool(DisableCiliumEndpointCRDName)
	c.DisableK8sServices = viper.GetBool(DisableK8sServices)
	c.EgressMasqueradeInterfaces = viper.GetString(EgressMasqueradeInterfaces)
	c.EnableHostReachableServices = viper.GetBool(EnableHostReachableServices)
	c.EnableRemoteNodeIdentity = viper.GetBool(EnableRemoteNodeIdentity)
	c.DockerEndpoint = viper.GetString(Docker)
	c.EnableAutoDirectRouting = viper.GetBool(EnableAutoDirectRoutingName)
	c.EnableEndpointRoutes = viper.GetBool(EnableEndpointRoutes)
	c.EnableHealthChecking = viper.GetBool(EnableHealthChecking)
	c.EnableEndpointHealthChecking = viper.GetBool(EnableEndpointHealthChecking)
	c.EnableLocalNodeRoute = viper.GetBool(EnableLocalNodeRoute)
	c.EnablePolicy = strings.ToLower(viper.GetString(EnablePolicy))
	c.EnableExternalIPs = viper.GetBool(EnableExternalIPs)
	c.EnableL7Proxy = viper.GetBool(EnableL7Proxy)
	c.EnableTracing = viper.GetBool(EnableTracing)
	c.EnableNodePort = viper.GetBool(EnableNodePort)
	c.NodePortMode = viper.GetString(NodePortMode)
	c.KubeProxyReplacement = viper.GetString(KubeProxyReplacement)
	c.EncryptInterface = viper.GetString(EncryptInterface)
	c.EncryptNode = viper.GetBool(EncryptNode)
	c.EnvoyLogPath = viper.GetString(EnvoyLog)
	c.ForceLocalPolicyEvalAtSource = viper.GetBool(ForceLocalPolicyEvalAtSource)
	c.HostDevice = getHostDevice()
	c.HTTPIdleTimeout = viper.GetInt(HTTPIdleTimeout)
	c.HTTPMaxGRPCTimeout = viper.GetInt(HTTPMaxGRPCTimeout)
	c.HTTPRequestTimeout = viper.GetInt(HTTPRequestTimeout)
	c.HTTPRetryCount = viper.GetInt(HTTPRetryCount)
	c.HTTPRetryTimeout = viper.GetInt(HTTPRetryTimeout)
	c.IdentityChangeGracePeriod = viper.GetDuration(IdentityChangeGracePeriod)
	c.IPAM = viper.GetString(IPAM)
	c.IPv4Range = viper.GetString(IPv4Range)
	c.IPv4NodeAddr = viper.GetString(IPv4NodeAddr)
	c.IPv4ServiceRange = viper.GetString(IPv4ServiceRange)
	c.IPv6ClusterAllocCIDR = viper.GetString(IPv6ClusterAllocCIDRName)
	c.IPv6NodeAddr = viper.GetString(IPv6NodeAddr)
	c.IPv6Range = viper.GetString(IPv6Range)
	c.IPv6ServiceRange = viper.GetString(IPv6ServiceRange)
	c.K8sAPIServer = viper.GetString(K8sAPIServer)
	c.K8sEnableK8sEndpointSlice = viper.GetBool(K8sEnableEndpointSlice)
	c.K8sKubeConfigPath = viper.GetString(K8sKubeConfigPath)
	c.K8sRequireIPv4PodCIDR = viper.GetBool(K8sRequireIPv4PodCIDRName)
	c.K8sRequireIPv6PodCIDR = viper.GetBool(K8sRequireIPv6PodCIDRName)
	c.K8sServiceCacheSize = uint(viper.GetInt(K8sServiceCacheSize))
	c.K8sForceJSONPatch = viper.GetBool(K8sForceJSONPatch)
	c.K8sEventHandover = viper.GetBool(K8sEventHandover)
	c.K8sWatcherQueueSize = uint(viper.GetInt(K8sWatcherQueueSize))
	c.K8sWatcherEndpointSelector = viper.GetString(K8sWatcherEndpointSelector)
	c.KeepTemplates = viper.GetBool(KeepBPFTemplates)
	c.KeepConfig = viper.GetBool(KeepConfig)
	c.KVStore = viper.GetString(KVStore)
	c.KVstoreLeaseTTL = viper.GetDuration(KVstoreLeaseTTL)
	c.KVstoreKeepAliveInterval = c.KVstoreLeaseTTL / defaults.KVstoreKeepAliveIntervalFactor
	c.KVstorePeriodicSync = viper.GetDuration(KVstorePeriodicSync)
	c.KVstoreConnectivityTimeout = viper.GetDuration(KVstoreConnectivityTimeout)
	c.IPAllocationTimeout = viper.GetDuration(IPAllocationTimeout)
	c.LabelPrefixFile = viper.GetString(LabelPrefixFile)
	c.Labels = viper.GetStringSlice(Labels)
	c.LibDir = viper.GetString(LibDir)
	c.LogDriver = viper.GetStringSlice(LogDriver)
	c.LogSystemLoadConfig = viper.GetBool(LogSystemLoadConfigName)
	c.Logstash = viper.GetBool(Logstash)
	c.LoopbackIPv4 = viper.GetString(LoopbackIPv4)
	c.Masquerade = viper.GetBool(Masquerade)
	c.InstallIptRules = viper.GetBool(InstallIptRules)
	c.IPSecKeyFile = viper.GetString(IPSecKeyFileName)
	c.ModePreFilter = viper.GetString(PrefilterMode)
	c.MonitorAggregation = viper.GetString(MonitorAggregationName)
	c.MonitorAggregationInterval = viper.GetDuration(MonitorAggregationInterval)
	c.MonitorQueueSize = viper.GetInt(MonitorQueueSizeName)
	c.MTU = viper.GetInt(MTUName)
	c.NAT46Range = viper.GetString(NAT46Range)
	c.FlannelMasterDevice = viper.GetString(FlannelMasterDevice)
	c.FlannelUninstallOnExit = viper.GetBool(FlannelUninstallOnExit)
	c.PolicyMapMaxEntries = viper.GetInt(PolicyMapEntriesName)
	c.PProf = viper.GetBool(PProf)
	c.PreAllocateMaps = viper.GetBool(PreAllocateMapsName)
	c.PrependIptablesChains = viper.GetBool(PrependIptablesChainsName)
	c.PrometheusServeAddr = getPrometheusServerAddr()
	c.ProxyConnectTimeout = viper.GetInt(ProxyConnectTimeout)
	c.BlacklistConflictingRoutes = viper.GetBool(BlacklistConflictingRoutes)
	c.ReadCNIConfiguration = viper.GetString(ReadCNIConfiguration)
	c.RestoreState = viper.GetBool(Restore)
	c.RunDir = viper.GetString(StateDir)
	c.SidecarIstioProxyImage = viper.GetString(SidecarIstioProxyImage)
	c.UseSingleClusterRoute = viper.GetBool(SingleClusterRouteName)
	c.SocketPath = viper.GetString(SocketPath)
	c.SockopsEnable = viper.GetBool(SockopsEnableName)
	c.TracePayloadlen = viper.GetInt(TracePayloadlen)
	c.Tunnel = viper.GetString(TunnelName)
	c.Version = viper.GetString(Version)
	c.WriteCNIConfigurationWhenReady = viper.GetString(WriteCNIConfigurationWhenReady)
	c.PolicyTriggerInterval = viper.GetDuration(PolicyTriggerInterval)
	c.CTMapEntriesTimeoutTCP = viper.GetDuration(CTMapEntriesTimeoutTCPName)
	c.CTMapEntriesTimeoutAny = viper.GetDuration(CTMapEntriesTimeoutAnyName)
	c.CTMapEntriesTimeoutSVCTCP = viper.GetDuration(CTMapEntriesTimeoutSVCTCPName)
	c.CTMapEntriesTimeoutSVCAny = viper.GetDuration(CTMapEntriesTimeoutSVCAnyName)
	c.CTMapEntriesTimeoutSYN = viper.GetDuration(CTMapEntriesTimeoutSYNName)
	c.CTMapEntriesTimeoutFIN = viper.GetDuration(CTMapEntriesTimeoutFINName)
	c.EnableIPv4FragmentsTracking = viper.GetBool(EnableIPv4FragmentsTrackingName)

	if nativeCIDR := viper.GetString(IPv4NativeRoutingCIDR); nativeCIDR != "" {
		c.ipv4NativeRoutingCIDR = cidr.MustParseCIDR(nativeCIDR)
	}

	// toFQDNs options
	// When the poller is enabled, the default MinTTL is lowered. This is to
	// avoid caching large sets of identities generated by a poller (it runs
	// every 5s). Without the poller, a longer default is better because it
	// avoids confusion about dropped connections.
	c.ToFQDNsEnablePoller = viper.GetBool(ToFQDNsEnablePoller)
	c.ToFQDNsEnablePollerEvents = viper.GetBool(ToFQDNsEnablePollerEvents)
	c.ToFQDNsMaxIPsPerHost = viper.GetInt(ToFQDNsMaxIPsPerHost)
	if maxZombies := viper.GetInt(ToFQDNsMaxDeferredConnectionDeletes); maxZombies >= 0 {
		c.ToFQDNsMaxDeferredConnectionDeletes = viper.GetInt(ToFQDNsMaxDeferredConnectionDeletes)
	} else {
		log.Fatal("tofqdns-max-deferred-connection-deletes must be positive, or 0 to disable deferred connection deletion")
	}
	switch {
	case viper.IsSet(ToFQDNsMinTTL): // set by user
		c.ToFQDNsMinTTL = viper.GetInt(ToFQDNsMinTTL)
	case c.ToFQDNsEnablePoller:
		c.ToFQDNsMinTTL = defaults.ToFQDNsMinTTLPoller
	default:
		c.ToFQDNsMinTTL = defaults.ToFQDNsMinTTL
	}
	c.ToFQDNsProxyPort = viper.GetInt(ToFQDNsProxyPort)
	c.ToFQDNsPreCache = viper.GetString(ToFQDNsPreCache)

	// Convert IP strings into net.IPNet types
	subnets, invalid := ip.ParseCIDRs(viper.GetStringSlice(IPv4PodSubnets))
	if len(invalid) > 0 {
		log.WithFields(
			logrus.Fields{
				"Subnets": invalid,
			}).Warning("IPv4PodSubnets parameter can not be parsed.")
	}
	c.IPv4PodSubnets = subnets

	subnets, invalid = ip.ParseCIDRs(viper.GetStringSlice(IPv6PodSubnets))
	if len(invalid) > 0 {
		log.WithFields(
			logrus.Fields{
				"Subnets": invalid,
			}).Warning("IPv6PodSubnets parameter can not be parsed.")
	}
	c.IPv6PodSubnets = subnets

	err = c.populateNodePortRange()
	if err != nil {
		log.WithError(err).Fatal("Failed to populate NodePortRange")
	}

	hostServicesProtos := viper.GetStringSlice(HostReachableServicesProtos)
	if len(hostServicesProtos) > 2 {
		log.Fatal("Unable to parse protocols for host reachable services!")
	}
	for i := 0; i < len(hostServicesProtos); i++ {
		switch strings.ToLower(hostServicesProtos[i]) {
		case HostServicesTCP:
			c.EnableHostServicesTCP = true
		case HostServicesUDP:
			c.EnableHostServicesUDP = true
		default:
			log.Fatalf("Unable to parse protocol %s for host reachable services!",
				hostServicesProtos[i])
		}
	}

	monitorAggregationFlags := viper.GetStringSlice(MonitorAggregationFlags)
	var ctMonitorReportFlags uint16
	for i := 0; i < len(monitorAggregationFlags); i++ {
		value := strings.ToLower(monitorAggregationFlags[i])
		flag, exists := TCPFlags[value]
		if !exists {
			log.Fatalf("Unable to parse TCP flag %q for %s!",
				value, MonitorAggregationFlags)
		}
		ctMonitorReportFlags |= flag
	}
	c.MonitorAggregationFlags = ctMonitorReportFlags

	// Map options
	if m := viper.GetStringMapString(FixedIdentityMapping); len(m) != 0 {
		c.FixedIdentityMapping = m
	}

	if m := viper.GetStringMapString(KVStoreOpt); len(m) != 0 {
		c.KVStoreOpt = m
	}

	if m := viper.GetStringMapString(LogOpt); len(m) != 0 {
		c.LogOpt = m
	}

	if val := viper.GetInt(ConntrackGarbageCollectorIntervalDeprecated); val != 0 {
		c.ConntrackGCInterval = time.Duration(val) * time.Second
	} else {
		c.ConntrackGCInterval = viper.GetDuration(ConntrackGCInterval)
	}

	if c.MonitorQueueSize == 0 {
		c.MonitorQueueSize = runtime.NumCPU() * defaults.MonitorQueueSizePerCPU
		if c.MonitorQueueSize > defaults.MonitorQueueSizePerCPUMaximum {
			c.MonitorQueueSize = defaults.MonitorQueueSizePerCPUMaximum
		}
	}

	// Metrics Setup
	defaultMetrics := metrics.DefaultMetrics()
	for _, metric := range viper.GetStringSlice(Metrics) {
		switch metric[0] {
		case '+':
			defaultMetrics[metric[1:]] = struct{}{}
		case '-':
			delete(defaultMetrics, metric[1:])
		}
	}
	var collectors []prometheus.Collector
	metricsSlice := common.MapStringStructToSlice(defaultMetrics)
	c.MetricsConfig, collectors = metrics.CreateConfiguration(metricsSlice)
	metrics.MustRegister(collectors...)

	if err := c.parseExcludedLocalAddresses(viper.GetStringSlice(ExcludeLocalAddress)); err != nil {
		log.WithError(err).Fatalf("Unable to parse excluded local addresses")
	}

	c.IdentityAllocationMode = viper.GetString(IdentityAllocationMode)
	switch c.IdentityAllocationMode {
	// This is here for tests. Some call Populate without the normal init
	case "":
		c.IdentityAllocationMode = IdentityAllocationModeKVstore

	case IdentityAllocationModeKVstore, IdentityAllocationModeCRD:
		// c.IdentityAllocationMode is set above

	default:
		log.Fatalf("Invalid identity allocation mode %q. It must be one of %s or %s", c.IdentityAllocationMode, IdentityAllocationModeKVstore, IdentityAllocationModeCRD)
	}
	if c.KVStore == "" {
		if c.IdentityAllocationMode != IdentityAllocationModeCRD {
			log.Warningf("Running Cilium with %q=%q requires identity allocation via CRDs. Changing %s to %q", KVStore, c.KVStore, IdentityAllocationMode, IdentityAllocationModeCRD)
			c.IdentityAllocationMode = IdentityAllocationModeCRD
		}
		if c.DisableCiliumEndpointCRD {
			log.Warningf("Running Cilium with %q=%q requires endpoint CRDs. Changing %s to %t", KVStore, c.KVStore, DisableCiliumEndpointCRDName, false)
			c.DisableCiliumEndpointCRD = false
		}
	}

	// Hidden options
	c.ConfigFile = viper.GetString(ConfigFile)
	c.HTTP403Message = viper.GetString(HTTP403Message)
	c.DisableEnvoyVersionCheck = viper.GetBool(DisableEnvoyVersionCheck)
	c.K8sNamespace = viper.GetString(K8sNamespaceName)
	c.MaxControllerInterval = viper.GetInt(MaxCtrlIntervalName)
	c.SidecarHTTPProxy = viper.GetBool(SidecarHTTPProxy)
	c.PolicyQueueSize = sanitizeIntParam(PolicyQueueSize, defaults.PolicyQueueSize)
	c.EndpointQueueSize = sanitizeIntParam(EndpointQueueSize, defaults.EndpointQueueSize)
	c.SelectiveRegeneration = viper.GetBool(SelectiveRegeneration)
	c.SkipCRDCreation = viper.GetBool(SkipCRDCreation)
	c.DisableCNPStatusUpdates = viper.GetBool(DisableCNPStatusUpdates)
	c.AwsReleaseExcessIps = viper.GetBool(AwsReleaseExcessIps)
}

func (c *DaemonConfig) populateNodePortRange() error {
	nodePortRange := viper.GetStringSlice(NodePortRange)
	switch len(nodePortRange) {
	case 2:
		var err error

		c.NodePortMin, err = strconv.Atoi(nodePortRange[0])
		if err != nil {
			return fmt.Errorf("Unable to parse min port value for NodePort range: %s", err.Error())
		}
		c.NodePortMax, err = strconv.Atoi(nodePortRange[1])
		if err != nil {
			return fmt.Errorf("Unable to parse max port value for NodePort range: %s", err.Error())
		}
		if c.NodePortMax <= c.NodePortMin {
			return errors.New("NodePort range min port must be smaller than max port")
		}
	case 0:
		log.Warning("NodePort range was set but is empty.")
	default:
		return fmt.Errorf("Unable to parse min/max port value for NodePort range: %s", NodePortRange)
	}

	return nil
}

func sanitizeIntParam(paramName string, paramDefault int) int {
	intParam := viper.GetInt(paramName)
	if intParam <= 0 {
		log.WithFields(
			logrus.Fields{
				"parameter":    paramName,
				"defaultValue": paramDefault,
			}).Warning("user-provided parameter had value <= 0 , which is invalid ; setting to default")
		return paramDefault
	}
	return intParam
}

func getIPv4Enabled() bool {
	if viper.GetBool(LegacyDisableIPv4Name) {
		return false
	}

	return viper.GetBool(EnableIPv4Name)
}

func getPrometheusServerAddr() string {
	promAddr := viper.GetString(PrometheusServeAddr)
	if promAddr == "" {
		return viper.GetString("prometheus-serve-addr-deprecated")
	}
	return promAddr
}

func getHostDevice() string {
	hostDevice := viper.GetString(FlannelMasterDevice)
	if hostDevice == "" {
		return defaults.HostDevice
	}
	return hostDevice
}
