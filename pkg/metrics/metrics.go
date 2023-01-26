// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package metrics holds prometheus metrics objects and related utility functions. It
// does not abstract away the prometheus client but the caller rarely needs to
// refer to prometheus directly.
package metrics

// Adding a metric
// - Add a metric object of the appropriate type as an exported variable
// - Register the new object in the init function

import (
	"regexp"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	// ErrorTimeout is the value used to notify timeout errors.
	ErrorTimeout = "timeout"

	// ErrorProxy is the value used to notify errors on Proxy.
	ErrorProxy = "proxy"

	// L7DNS is the value used to report DNS label on metrics
	L7DNS = "dns"

	// Namespace is used to scope metrics from cilium. It is prepended to metric
	// names and separated with a '_'
	Namespace = "cilium"
)

var (
	// SubsystemBPF is the subsystem to scope metrics related to the bpf syscalls.
	SubsystemBPF = metric.Subsystem{
		Name:    "bpf",
		DocName: "eBPF",
		Description: "Both ``bpf_maps_virtual_memory_max_bytes`` and ``bpf_progs_virtual_memory_max_bytes`` are " +
			"currently reporting the system-wide memory usage of eBPF that is directly and not directly managed by " +
			"Cilium. This might change in the future and only report the eBPF memory usage directly managed by Cilium.",
	}

	// SubsystemDatapath is the subsystem to scope metrics related to management of
	// the datapath. It is prepended to metric names and separated with a '_'.
	SubsystemDatapath = metric.Subsystem{
		Name:    "datapath",
		DocName: "Datapath",
	}

	// SubsystemAgent is the subsystem to scope metrics related to the cilium agent itself.
	SubsystemAgent = metric.Subsystem{
		Name:    "agent",
		DocName: "Agent",
	}

	// SubsystemFQDN is the subsystem to scope metrics related to the FQDN proxy.
	SubsystemIPCache = metric.Subsystem{
		Name:    "ipcache",
		DocName: "IPCache",
	}

	// SubsystemK8s is the subsystem to scope metrics related to Kubernetes
	SubsystemK8s = metric.Subsystem{
		Name:    "k8s",
		DocName: "Kubernetes",
	}

	// SubsystemK8sClient is the subsystem to scope metrics related to the kubernetes client.
	SubsystemK8sClient = metric.Subsystem{
		Name:    "k8s_client",
		DocName: "Kubernetes Client",
	}

	// SubsystemKVStore is the subsystem to scope metrics related to the kvstore.
	SubsystemKVStore = metric.Subsystem{
		Name:    "kvstore",
		DocName: "KVStore",
	}

	// SubsystemFQDN is the subsystem to scope metrics related to the FQDN proxy.
	SubsystemFQDN = metric.Subsystem{
		Name:    "fqdn",
		DocName: "FQDN",
	}

	// SubsystemNodes is the subsystem to scope metrics related to the node manager.
	SubsystemNodes = metric.Subsystem{
		Name:    "nodes",
		DocName: "Nodes",
	}

	// SubsystemTriggers is the subsystem to scope metrics related to the trigger package.
	SubsystemTriggers = metric.Subsystem{
		Name:    "triggers",
		DocName: "Triggers",
	}

	// SubsystemAPILimiter is the subsystem to scope metrics related to the API limiter package.
	SubsystemAPILimiter = metric.Subsystem{
		Name:    "api_limiter",
		DocName: "API Limiter",
	}

	// SubsystemNodeNeigh is the subsystem to scope metrics related to management of node neighbor.
	SubsystemNodeNeigh = metric.Subsystem{
		Name:    "node_neigh",
		DocName: "Node Neighbor",
	}

	// SubsystemClustermesh is the subsystem to scope metrics related to custer mesh.
	SubsystemClustermesh = metric.Subsystem{
		Name:    "clustermesh",
		DocName: "Clustermesh",
	}

	SubsystemPolicyL7 = metric.Subsystem{
		DocName: "Policy L7 (HTTP/Kafka)",
	}

	// LabelError indicates the type of error (string)
	LabelError = metric.LabelDescription{
		Name:        "error",
		Description: "Indicates the type of error (string)",
	}

	// LabelOutcome indicates whether the outcome of the operation was successful or not
	LabelOutcome = metric.LabelDescription{
		Name:        "outcome",
		Description: "Indicates whether the outcome of the operation was successful or not",
		KnownValues: []metric.KnownValue{
			LabelValueOutcomeSuccess,
			LabelValueOutcomeFail,
		},
	}

	LabelValueOutcomeSuccess = metric.KnownValue{
		Name: "success",
	}

	LabelValueOutcomeFail = metric.KnownValue{
		Name: "fail",
	}

	// LabelAttempts is the number of attempts it took to complete the operation
	LabelAttempts = metric.LabelDescription{
		Name:        "attempts",
		Description: "The number of attempts it took to complete the operation",
	}

	// LabelDatapathArea marks which area the metrics are related to (eg, which BPF map)
	LabelDatapathArea = metric.LabelDescription{
		Name:        "area",
		Description: "Marks which area the metrics are related to (eg, which BPF map)",
	}

	// LabelDatapathName marks a unique identifier for this metric.
	// The name should be defined once for a given type of error.
	LabelDatapathName = metric.LabelDescription{
		Name: "name",
		Description: "marks a unique identifier for this metric. " +
			"The name should be defined once for a given type of error.",
	}

	// LabelDatapathFamily marks which protocol family (IPv4, IPV6) the metric is related to.
	LabelDatapathFamily = metric.LabelDescription{
		Name:        "family",
		Description: "Marks which protocol family (IPv4, IPV6) the metric is related to.",
	}

	// LabelProtocol marks the L4 protocol (TCP, ANY) for the metric.
	LabelProtocol = metric.LabelDescription{
		Name:        "protocol",
		Description: "Marks the L4 protocol (TCP, ANY) for the metric.",
	}

	// LabelSignalType marks the signal name
	LabelSignalType = metric.LabelDescription{
		Name:        "signal",
		Description: "Marks the signal name",
	}

	// LabelSignalData marks the signal data
	LabelSignalData = metric.LabelDescription{
		Name:        "data",
		Description: "Marks the signal data",
	}

	// LabelStatus the label from completed task
	LabelStatus = metric.LabelDescription{
		Name:        "status",
		Description: "The label from completed task",
	}

	// LabelPolicyEnforcement is the label used to see the enforcement status
	LabelPolicyEnforcement = metric.LabelDescription{
		Name:        "enforcement",
		Description: "The label used to see the enforcement status",
	}

	// LabelPolicySource is the label used to see the enforcement status
	LabelPolicySource = metric.LabelDescription{
		Name:        "source",
		Description: "The label used to see the enforcement status",
	}

	// LabelScope is the label used to defined multiples scopes in the same
	// metric. For example, one counter may measure a metric over the scope of
	// the entire event (scope=global), or just part of an event
	// (scope=slow_path)
	LabelScope = metric.LabelDescription{
		Name: "scope",
		Description: "Used to defined multiples scopes in the same. For example, one counter may measure a metric " +
			"over the scope of the entire event (scope=global), or just part of an event (scope=slow_path)",
		// TODO looks like this is a label with known values
	}

	// LabelProtocolL7 is the label used when working with layer 7 protocols.
	LabelProtocolL7 = metric.LabelDescription{
		Name:        "protocol_l7",
		Description: "The label used when working with layer 7 protocols.",
	}

	// LabelBuildState is the state a build queue entry is in
	LabelBuildState = metric.LabelDescription{
		Name:        "state",
		Description: "The state a build queue entry is in",
	}

	// LabelBuildQueueName is the name of the build queue
	LabelBuildQueueName = metric.LabelDescription{
		Name:        "name",
		Description: "The name of the build queue",
	}

	// LabelAction is the label used to defined what kind of action was performed in a metric
	LabelAction = metric.LabelDescription{
		Name:        "action",
		Description: "The label used to defined what kind of action was performed in a metric",
	}

	// LabelSubsystem is the label used to refer to any of the child process
	// started by cilium (Envoy, monitor, etc..)
	LabelSubsystem = metric.LabelDescription{
		Name:        "subsystem",
		Description: "The label used to refer to any of the child process started by cilium (Envoy, monitor, etc..)",
	}

	// LabelKind is the kind of a label
	LabelKind = metric.LabelDescription{
		Name:        "kind",
		Description: "The kind of a label",
	}

	// LabelEventSourceAPI marks event-related metrics that come from the API
	LabelEventSourceAPI = metric.KnownValue{
		Name:        "api",
		Description: "Marks event-related metrics that come from the API",
	}

	// LabelEventSourceK8s marks event-related metrics that come from k8s
	LabelEventSourceK8s = metric.KnownValue{
		Name:        "k8s",
		Description: "Marks event-related metrics that come from k8s",
	}

	// LabelEventSourceFQDN marks event-related metrics that come from pkg/fqdn
	LabelEventSourceFQDN = metric.KnownValue{
		Name:        "fqdn",
		Description: "Marks event-related metrics that come from pkg/fqdn",
	}

	// LabelEventSourceContainerd marks event-related metrics that come from docker
	LabelEventSourceContainerd = metric.KnownValue{
		Name:        "docker",
		Description: "Marks event-related metrics that come from docker",
	}

	// LabelEventSource is the source of a label for event metrics
	// i.e. k8s, containerd, api.
	LabelEventSource = metric.LabelDescription{
		Name:        "source",
		Description: "The source of a label for event metrics i.e. k8s, containerd, api.",
		KnownValues: []metric.KnownValue{
			LabelEventSourceAPI,
			LabelEventSourceK8s,
			LabelEventSourceFQDN,
			LabelEventSourceContainerd,
		},
	}

	// LabelPath is the label for the API path
	LabelPath = metric.LabelDescription{
		Name:        "path",
		Description: "The API path",
	}
	// LabelMethod is the label for the HTTP method
	LabelMethod = metric.LabelDescription{
		Name:        "method",
		Description: "The HTTP method",
	}
	// LabelAPIReturnCode is the HTTP code returned for that API path
	LabelAPIReturnCode = metric.LabelDescription{
		Name:        "return_code",
		Description: "The HTTP code returned for that API path",
	}

	// LabelOperation is the label for BPF maps operations
	LabelOperation = metric.LabelDescription{
		Name:        "operation",
		Description: "The label for BPF maps operations",
	}

	// LabelMapName is the label for the BPF map name
	LabelMapName = metric.LabelDescription{
		Name:        "map_name",
		Description: "The label for the BPF map name",
	}

	// LabelVersion is the label for the version number
	LabelVersion = metric.LabelDescription{
		Name:        "version",
		Description: "The label for the version number",
	}

	// LabelDirection is the label for traffic direction
	LabelDirection = metric.LabelDescription{
		Name:        "direction",
		Description: "The label for traffic direction",
	}

	// LabelSourceCluster is the label for source cluster name
	LabelSourceCluster = metric.LabelDescription{
		Name:        "source_cluster",
		Description: "The label for source cluster name",
	}

	// LabelSourceNodeName is the label for source node name
	LabelSourceNodeName = metric.LabelDescription{
		Name:        "source_node_name",
		Description: "The label for source node name",
	}

	// LabelTargetCluster is the label for target cluster name
	LabelTargetCluster = metric.LabelDescription{
		Name:        "target_cluster",
		Description: "The label for target cluster name",
	}

	// LabelTargetNodeIP is the label for target node IP
	LabelTargetNodeIP = metric.LabelDescription{
		Name:        "target_node_ip",
		Description: "The label for target node IP",
	}

	// LabelTargetNodeName is the label for target node name
	LabelTargetNodeName = metric.LabelDescription{
		Name:        "target_node_name",
		Description: "The label for target node name",
	}

	// LabelTargetNodeType is the label for target node type (local_node, remote_intra_cluster, vs remote_inter_cluster)
	LabelTargetNodeType = metric.LabelDescription{
		Name:        "target_node_type",
		Description: "The label for target node type (local_node, remote_intra_cluster, vs remote_inter_cluster)",
	}

	LabelLocationLocalNode = metric.LabelDescription{
		Name: "local_node",
	}
	LabelLocationRemoteIntraCluster = metric.LabelDescription{
		Name: "remote_intra_cluster",
	}
	LabelLocationRemoteInterCluster = metric.LabelDescription{
		Name: "remote_inter_cluster",
	}

	// LabelType is the label for type in general (e.g. endpoint, node)
	LabelType = metric.LabelDescription{
		Name: "type",
	}
	LabelPeerEndpoint = metric.LabelDescription{
		Name: "endpoint",
	}
	LabelPeerNode = metric.LabelDescription{
		Name: "node",
	}

	LabelTrafficHTTP = metric.LabelDescription{
		Name: "http",
	}
	LabelTrafficICMP = metric.LabelDescription{
		Name: "icmp",
	}

	LabelAddressType = metric.LabelDescription{
		Name: "address_type",
	}
	LabelAddressTypePrimary = metric.LabelDescription{
		Name: "primary",
	}
	LabelAddressTypeSecondary = metric.LabelDescription{
		Name: "secondary",
	}
)

// TODO(dylandreimerink): get rid of these globals by modularizing their dependents
var (
	// goCustomCollectorsRX tracks enabled go runtime metrics.
	goCustomCollectorsRX = regexp.MustCompile(`^/sched/latencies:seconds`)

	// BootstrapTimes is the durations of cilium-agent bootstrap sequence.
	BootstrapTimes metric.Vec[metric.Observer] = &noopVecHistogram{}

	// APIInteractions is the total time taken to process an API call made
	// to the cilium-agent
	APIInteractions metric.Vec[metric.Observer] = &noopVecHistogram{}

	// Status

	// NodeConnectivityStatus is the connectivity status between local node to
	// other node intra or inter cluster.
	NodeConnectivityStatus metric.Vec[metric.Gauge] = &noopVecGauge{}

	// NodeConnectivityLatency is the connectivity latency between local node to
	// other node intra or inter cluster.
	NodeConnectivityLatency metric.Vec[metric.Gauge] = &noopVecGauge{}

	// Endpoint

	// Endpoint is a function used to collect this metric.
	// It must be thread-safe.
	Endpoint metric.GaugeFunc

	// EndpointRegenerationTotal is a count of the number of times any endpoint
	// has been regenerated and success/fail outcome
	EndpointRegenerationTotal metric.Vec[metric.Counter] = &noopVecCounter{}

	// EndpointStateCount is the total count of the endpoints in various states.
	EndpointStateCount metric.Vec[metric.Gauge] = &noopVecGauge{}

	// EndpointRegenerationTimeStats is the total time taken to regenerate
	// endpoints, labeled by span name and status ("success" or "failure")
	EndpointRegenerationTimeStats metric.Vec[metric.Observer] = &noopVecHistogram{}

	// EndpointPropagationDelay is the delay between creation of local CiliumEndpoint
	// and update for that CiliumEndpoint received through CiliumEndpointSlice.
	// Measure of local CEP roundtrip time with CiliumEndpointSlice feature enabled.
	EndpointPropagationDelay metric.Vec[metric.Observer] = &noopVecHistogram{}

	// Policy
	// Policy is the number of policies loaded into the agent
	Policy metric.Gauge = &noopGauge{}

	// PolicyRegenerationCount is the total number of successful policy
	// regenerations.
	PolicyRegenerationCount metric.Counter = &noopCounter{}

	// PolicyRegenerationTimeStats is the total time taken to generate policies
	PolicyRegenerationTimeStats metric.Vec[metric.Observer] = &noopVecHistogram{}

	// PolicyRevision is the current policy revision number for this agent
	PolicyRevision metric.Gauge = &noopGauge{}

	// PolicyImportErrorsTotal is a count of failed policy imports
	PolicyImportErrorsTotal metric.Counter = &noopCounter{}

	// PolicyChangeTotal is a count of policy changes by outcome ("success" or
	// "failure")
	PolicyChangeTotal metric.Vec[metric.Counter] = &noopVecCounter{}

	// PolicyEndpointStatus is the number of endpoints with policy labeled by enforcement type
	PolicyEndpointStatus metric.Vec[metric.Gauge] = &noopVecGauge{}

	// PolicyImplementationDelay is a distribution of times taken from adding a
	// policy (and incrementing the policy revision) to seeing it in the datapath
	// per Endpoint. This reflects the actual delay perceived by traffic flowing
	// through the datapath. The longest times will roughly correlate with the
	// time taken to fully deploy an endpoint.
	PolicyImplementationDelay metric.Vec[metric.Observer] = &noopVecHistogram{}

	// Identity

	// Identity is the number of identities currently in use on the node by type
	Identity metric.Vec[metric.Gauge] = &noopVecGauge{}

	// Events

	// EventTS*is the time in seconds since epoch that we last received an
	// event that we will handle
	// source is one of k8s, docker or apia

	// EventTS is the timestamp of k8s resource events.
	EventTS metric.Vec[metric.Gauge] = &noopVecGauge{}

	// EventLagK8s is the lag calculation for k8s Pod events.
	EventLagK8s metric.Gauge = &noopGauge{}

	// L7 statistics

	// ProxyRedirects is the number of redirects labeled by protocol
	ProxyRedirects metric.Vec[metric.Gauge] = &noopVecGauge{}

	// ProxyPolicyL7Total is a count of all l7 requests handled by proxy
	ProxyPolicyL7Total metric.Vec[metric.Counter] = &noopVecCounter{}

	// ProxyParseErrors is a count of failed parse errors on proxy
	// Deprecated: in favor of ProxyPolicyL7Total
	ProxyParseErrors metric.Counter = &noopCounter{}

	// ProxyForwarded is a count of all forwarded requests by proxy
	// Deprecated: in favor of ProxyPolicyL7Total
	ProxyForwarded metric.Counter = &noopCounter{}

	// ProxyDenied is a count of all denied requests by policy by the proxy
	// Deprecated: in favor of ProxyPolicyL7Total
	ProxyDenied metric.Counter = &noopCounter{}

	// ProxyReceived is a count of all received requests by the proxy
	// Deprecated: in favor of ProxyPolicyL7Total
	ProxyReceived metric.Counter = &noopCounter{}

	// ProxyUpstreamTime is how long the upstream server took to reply labeled
	// by error, protocol and span time
	ProxyUpstreamTime metric.Vec[metric.Observer] = &noopVecHistogram{}

	// ProxyDatapathUpdateTimeout is a count of all the timeouts encountered while
	// updating the datapath due to an FQDN IP update
	ProxyDatapathUpdateTimeout metric.Counter = &noopCounter{}

	// L3-L4 statistics

	// DropCount is the total drop requests,
	// tagged by drop reason and direction(ingress/egress)
	DropCount metric.Vec[metric.Counter] = &noopVecCounter{}

	// DropBytes is the total dropped bytes,
	// tagged by drop reason and direction(ingress/egress)
	DropBytes metric.Vec[metric.Counter] = &noopVecCounter{}

	// ForwardCount is the total forwarded packets,
	// tagged by ingress/egress direction
	ForwardCount metric.Vec[metric.Counter] = &noopVecCounter{}

	// ForwardBytes is the total forwarded bytes,
	// tagged by ingress/egress direction
	ForwardBytes metric.Vec[metric.Counter] = &noopVecCounter{}

	// Datapath statistics

	// ConntrackGCRuns is the number of times that the conntrack GC
	// process was run.
	ConntrackGCRuns metric.Vec[metric.Counter] = &noopVecCounter{}

	// ConntrackGCKeyFallbacks number of times that the conntrack key fallback was invalid.
	ConntrackGCKeyFallbacks metric.Vec[metric.Counter] = &noopVecCounter{}

	// ConntrackGCSize the number of entries in the conntrack table
	ConntrackGCSize metric.Vec[metric.Gauge] = &noopVecGauge{}

	// NatGCSize the number of entries in the nat table
	NatGCSize metric.Vec[metric.Gauge] = &noopVecGauge{}

	// ConntrackGCDuration the duration of the conntrack GC process in milliseconds.
	ConntrackGCDuration metric.Vec[metric.Observer] = &noopVecHistogram{}

	// ConntrackDumpReset marks the count for conntrack dump resets
	ConntrackDumpResets metric.Vec[metric.Counter] = &noopVecCounter{}

	// Signals

	// SignalsHandled is the number of signals received.
	SignalsHandled metric.Vec[metric.Counter] = &noopVecCounter{}

	// Services

	// ServicesCount number of services
	ServicesCount metric.Vec[metric.Counter] = &noopVecCounter{}

	// ControllerRuns is the number of times that a controller process runs.
	ControllerRuns metric.Vec[metric.Counter] = &noopVecCounter{}

	// ControllerRunsDuration the duration of the controller process in seconds
	ControllerRunsDuration metric.Vec[metric.Observer] = &noopVecHistogram{}

	// subprocess, labeled by Subsystem
	SubprocessStart metric.Vec[metric.Counter] = &noopVecCounter{}

	// Kubernetes Events

	// KubernetesEventProcessed is the number of Kubernetes events
	// processed labeled by scope, action and execution result
	KubernetesEventProcessed metric.Vec[metric.Counter] = &noopVecCounter{}

	// KubernetesEventReceived is the number of Kubernetes events received
	// labeled by scope, action, valid data and equalness.
	KubernetesEventReceived metric.Vec[metric.Counter] = &noopVecCounter{}

	// Kubernetes interactions

	// KubernetesAPIInteractions is the total time taken to process an API call made
	// to the kube-apiserver
	KubernetesAPIInteractions metric.Vec[metric.Observer] = &noopVecHistogram{}

	// KubernetesAPICallsTotal is the counter for all API calls made to
	// kube-apiserver.
	KubernetesAPICallsTotal metric.Vec[metric.Counter] = &noopVecCounter{}

	// KubernetesCNPStatusCompletion is the number of seconds it takes to
	// complete a CNP status update
	KubernetesCNPStatusCompletion metric.Vec[metric.Observer] = &noopVecHistogram{}

	// TerminatingEndpointsEvents is the number of terminating endpoint events received from kubernetes.
	TerminatingEndpointsEvents metric.Counter = &noopCounter{}

	// IPAM events

	// IpamEvent is the number of IPAM events received labeled by action and
	// datapath family type
	IpamEvent metric.Vec[metric.Counter] = &noopVecCounter{}

	// KVstore events

	// KVStoreOperationsDuration records the duration of kvstore operations
	KVStoreOperationsDuration metric.Vec[metric.Observer] = &noopVecHistogram{}

	// KVStoreEventsQueueDuration records the duration in seconds of time
	// received event was blocked before it could be queued
	KVStoreEventsQueueDuration metric.Vec[metric.Observer] = &noopVecHistogram{}

	// KVStoreQuorumErrors records the number of kvstore quorum errors
	KVStoreQuorumErrors metric.Vec[metric.Counter] = &noopVecCounter{}

	// FQDNGarbageCollectorCleanedTotal is the number of domains cleaned by the
	// GC job.
	FQDNGarbageCollectorCleanedTotal metric.Counter = &noopCounter{}

	// FQDNActiveNames is the number of domains inside the DNS cache that have
	// not expired (by TTL), per endpoint.
	FQDNActiveNames metric.Vec[metric.Gauge] = &noopVecGauge{}

	// FQDNActiveIPs is the number of IPs inside the DNS cache associated with
	// a domain that has not expired (by TTL) and are currently active, per
	// endpoint.
	FQDNActiveIPs metric.Vec[metric.Gauge] = &noopVecGauge{}

	// FQDNAliveZombieConnections is the number IPs associated with domains
	// that have expired (by TTL) yet still associated with an active
	// connection (aka zombie), per endpoint.
	FQDNAliveZombieConnections metric.Vec[metric.Gauge] = &noopVecGauge{}

	// FQDNSemaphoreRejectedTotal is the total number of DNS requests rejected
	// by the DNS proxy because too many requests were in flight, as enforced by
	// the admission semaphore.
	FQDNSemaphoreRejectedTotal metric.Counter = &noopCounter{}

	// IPCacheErrorsTotal is the total number of IPCache events handled in
	// the IPCache subsystem that resulted in errors.
	IPCacheErrorsTotal metric.Vec[metric.Counter] = &noopVecCounter{}

	// IPCacheEventsTotal is the total number of IPCache events handled in
	// the IPCache subsystem.
	IPCacheEventsTotal metric.Vec[metric.Counter] = &noopVecCounter{}

	// BPFSyscallDuration is the metric for bpf syscalls duration.
	BPFSyscallDuration metric.Vec[metric.Observer] = &noopVecHistogram{}

	// BPFMapOps is the metric to measure the number of operations done to a
	// bpf map.
	BPFMapOps metric.Vec[metric.Counter] = &noopVecCounter{}

	// TriggerPolicyUpdateTotal is the metric to count total number of
	// policy update triggers
	TriggerPolicyUpdateTotal metric.Vec[metric.Counter] = &noopVecCounter{}

	// TriggerPolicyUpdateFolds is the current level folding that is
	// happening when running policy update triggers
	TriggerPolicyUpdateFolds metric.Gauge = &noopGauge{}

	// TriggerPolicyUpdateCallDuration measures the latency and call
	// duration of policy update triggers
	TriggerPolicyUpdateCallDuration metric.Vec[metric.Observer] = &noopVecHistogram{}

	// VersionMetric labelled by Cilium version
	VersionMetric metric.Vec[metric.Gauge] = &noopVecGauge{}

	// ArpingRequestsTotal is the counter of the number of sent
	// (successful and failed) arping requests
	ArpingRequestsTotal metric.Vec[metric.Counter] = &noopVecCounter{}

	// NodeEventsReceived is the prometheus metric to track the number of
	// node events received
	NodeEventsReceived metric.Vec[metric.Counter] = &noopVecCounter{}

	// NumNodes is the prometheus metric to track the number of nodes
	// being managed
	NumNodes metric.Gauge = &noopGauge{}

	// DatapathValidations is the prometheus metric to track the
	// number of datapath node validation calls
	DatapathValidations metric.Counter = &noopCounter{}

	// TotalRemoteClusters is gauge metric keeping track of total number
	// of remote clusters.
	TotalRemoteClusters metric.Vec[metric.Gauge] = &noopVecGauge{}

	// LastFailureTimestamp is a gauge metric tracking the last failure timestamp
	LastFailureTimestamp metric.Vec[metric.Gauge] = &noopVecGauge{}

	// ReadinessStatus is a gauge metric tracking the readiness status of a remote cluster
	ReadinessStatus metric.Vec[metric.Gauge] = &noopVecGauge{}

	// TotalFailures is a gauge metric tracking the number of failures when connecting to a remote cluster
	TotalFailures metric.Vec[metric.Gauge] = &noopVecGauge{}

	// TotalNodes is a gauge metric tracking the number of total nodes in a remote cluster
	TotalNodes metric.Vec[metric.Gauge] = &noopVecGauge{}

	// TotalGlobalServices is the gauge metric for total of global services
	TotalGlobalServices metric.Vec[metric.Gauge] = &noopVecGauge{}

	// APILimiterWaitDuration is the gauge of the current mean, min, and
	// max wait duration
	APILimiterWaitDuration metric.Vec[metric.Gauge] = &noopVecGauge{}

	// APILimiterProcessingDuration is the gauge of the mean and estimated
	// processing duration
	APILimiterProcessingDuration metric.Vec[metric.Gauge] = &noopVecGauge{}

	// APILimiterRequestsInFlight is the gauge of the current and max
	// requests in flight
	APILimiterRequestsInFlight metric.Vec[metric.Gauge] = &noopVecGauge{}

	// APILimiterRateLimit is the gauge of the current rate limiting
	// configuration including limit and burst
	APILimiterRateLimit metric.Vec[metric.Gauge] = &noopVecGauge{}

	// APILimiterWaitHistoryDuration is a histogram that measures the
	// individual wait durations of API limiters
	APILimiterWaitHistoryDuration metric.Vec[metric.Observer] = &noopVecHistogram{}

	// APILimiterAdjustmentFactor is the gauge representing the latest
	// adjustment factor that was applied
	APILimiterAdjustmentFactor metric.Vec[metric.Gauge] = &noopVecGauge{}

	// APILimiterProcessedRequests is the counter of the number of
	// processed (successful and failed) requests
	APILimiterProcessedRequests metric.Vec[metric.Counter] = &noopVecCounter{}
)

type LegacyMetrics struct {
	BootstrapTimes metric.Vec[metric.Observer]

	// APIInteractions is the total time taken to process an API call made
	// to the cilium-agent
	APIInteractions metric.Vec[metric.Observer]

	// Status

	// NodeConnectivityStatus is the connectivity status between local node to
	// other node intra or inter cluster.
	NodeConnectivityStatus metric.Vec[metric.Gauge]

	// NodeConnectivityLatency is the connectivity latency between local node to
	// other node intra or inter cluster.
	NodeConnectivityLatency metric.Vec[metric.Gauge]

	// Endpoint

	// Endpoint is a function used to collect this metric.
	// It must be thread-safe.
	Endpoint metric.GaugeFunc

	// EndpointRegenerationTotal is a count of the number of times any endpoint
	// has been regenerated and success/fail outcome
	EndpointRegenerationTotal metric.Vec[metric.Counter]

	// EndpointStateCount is the total count of the endpoints in various states.
	EndpointStateCount metric.Vec[metric.Gauge]

	// EndpointRegenerationTimeStats is the total time taken to regenerate
	// endpoints, labeled by span name and status ("success" or "failure")
	EndpointRegenerationTimeStats metric.Vec[metric.Observer]

	// EndpointPropagationDelay is the delay between creation of local CiliumEndpoint
	// and update for that CiliumEndpoint received through CiliumEndpointSlice.
	// Measure of local CEP roundtrip time with CiliumEndpointSlice feature enabled.
	EndpointPropagationDelay metric.Vec[metric.Observer]

	// Policy
	// Policy is the number of policies loaded into the agent
	Policy metric.Gauge

	// PolicyRegenerationCount is the total number of successful policy
	// regenerations.
	PolicyRegenerationCount metric.Counter

	// PolicyRegenerationTimeStats is the total time taken to generate policies
	PolicyRegenerationTimeStats metric.Vec[metric.Observer]

	// PolicyRevision is the current policy revision number for this agent
	PolicyRevision metric.Gauge

	// PolicyImportErrorsTotal is a count of failed policy imports
	PolicyImportErrorsTotal metric.Counter

	// PolicyChangeTotal is a count of policy changes by outcome ("success" or
	// "failure")
	PolicyChangeTotal metric.Vec[metric.Counter]

	// PolicyEndpointStatus is the number of endpoints with policy labeled by enforcement type
	PolicyEndpointStatus metric.Vec[metric.Gauge]

	// PolicyImplementationDelay is a distribution of times taken from adding a
	// policy (and incrementing the policy revision) to seeing it in the datapath
	// per Endpoint. This reflects the actual delay perceived by traffic flowing
	// through the datapath. The longest times will roughly correlate with the
	// time taken to fully deploy an endpoint.
	PolicyImplementationDelay metric.Vec[metric.Observer]

	// Identity

	// Identity is the number of identities currently in use on the node by type
	Identity metric.Vec[metric.Gauge]

	// Events

	// EventTS*is the time in seconds since epoch that we last received an
	// event that we will handle
	// source is one of k8s, docker or apia

	// EventTS is the timestamp of k8s resource events.
	EventTS metric.Vec[metric.Gauge]

	// EventLagK8s is the lag calculation for k8s Pod events.
	EventLagK8s metric.Gauge

	// L7 statistics

	// ProxyRedirects is the number of redirects labeled by protocol
	ProxyRedirects metric.Vec[metric.Gauge]

	// ProxyPolicyL7Total is a count of all l7 requests handled by proxy
	ProxyPolicyL7Total metric.Vec[metric.Counter]

	// ProxyParseErrors is a count of failed parse errors on proxy
	// Deprecated: in favor of ProxyPolicyL7Total
	ProxyParseErrors metric.Counter

	// ProxyForwarded is a count of all forwarded requests by proxy
	// Deprecated: in favor of ProxyPolicyL7Total
	ProxyForwarded metric.Counter

	// ProxyDenied is a count of all denied requests by policy by the proxy
	// Deprecated: in favor of ProxyPolicyL7Total
	ProxyDenied metric.Counter

	// ProxyReceived is a count of all received requests by the proxy
	// Deprecated: in favor of ProxyPolicyL7Total
	ProxyReceived metric.Counter

	// ProxyUpstreamTime is how long the upstream server took to reply labeled
	// by error, protocol and span time
	ProxyUpstreamTime metric.Vec[metric.Observer]

	// ProxyDatapathUpdateTimeout is a count of all the timeouts encountered while
	// updating the datapath due to an FQDN IP update
	ProxyDatapathUpdateTimeout metric.Counter

	// L3-L4 statistics

	// DropCount is the total drop requests,
	// tagged by drop reason and direction(ingress/egress)
	DropCount metric.Vec[metric.Counter]

	// DropBytes is the total dropped bytes,
	// tagged by drop reason and direction(ingress/egress)
	DropBytes metric.Vec[metric.Counter]

	// ForwardCount is the total forwarded packets,
	// tagged by ingress/egress direction
	ForwardCount metric.Vec[metric.Counter]

	// ForwardBytes is the total forwarded bytes,
	// tagged by ingress/egress direction
	ForwardBytes metric.Vec[metric.Counter]

	// Datapath statistics

	// ConntrackGCRuns is the number of times that the conntrack GC
	// process was run.
	ConntrackGCRuns metric.Vec[metric.Counter]

	// ConntrackGCKeyFallbacks number of times that the conntrack key fallback was invalid.
	ConntrackGCKeyFallbacks metric.Vec[metric.Counter]

	// ConntrackGCSize the number of entries in the conntrack table
	ConntrackGCSize metric.Vec[metric.Gauge]

	// NatGCSize the number of entries in the nat table
	NatGCSize metric.Vec[metric.Gauge]

	// ConntrackGCDuration the duration of the conntrack GC process in milliseconds.
	ConntrackGCDuration metric.Vec[metric.Observer]

	// ConntrackDumpReset marks the count for conntrack dump resets
	ConntrackDumpResets metric.Vec[metric.Counter]

	// Signals

	// SignalsHandled is the number of signals received.
	SignalsHandled metric.Vec[metric.Counter]

	// Services

	// ServicesCount number of services
	ServicesCount metric.Vec[metric.Counter]

	// ControllerRuns is the number of times that a controller process runs.
	ControllerRuns metric.Vec[metric.Counter]

	// ControllerRunsDuration the duration of the controller process in seconds
	ControllerRunsDuration metric.Vec[metric.Observer]

	// subprocess, labeled by Subsystem
	SubprocessStart metric.Vec[metric.Counter]

	// Kubernetes Events

	// KubernetesEventProcessed is the number of Kubernetes events
	// processed labeled by scope, action and execution result
	KubernetesEventProcessed metric.Vec[metric.Counter]

	// KubernetesEventReceived is the number of Kubernetes events received
	// labeled by scope, action, valid data and equalness.
	KubernetesEventReceived metric.Vec[metric.Counter]

	// Kubernetes interactions

	// KubernetesAPIInteractions is the total time taken to process an API call made
	// to the kube-apiserver
	KubernetesAPIInteractions metric.Vec[metric.Observer]

	// KubernetesAPICallsTotal is the counter for all API calls made to
	// kube-apiserver.
	KubernetesAPICallsTotal metric.Vec[metric.Counter]

	// KubernetesCNPStatusCompletion is the number of seconds it takes to
	// complete a CNP status update
	KubernetesCNPStatusCompletion metric.Vec[metric.Observer]

	// TerminatingEndpointsEvents is the number of terminating endpoint events received from kubernetes.
	TerminatingEndpointsEvents metric.Counter

	// IPAM events

	// IpamEvent is the number of IPAM events received labeled by action and
	// datapath family type
	IpamEvent metric.Vec[metric.Counter]

	// KVstore events

	// KVStoreOperationsDuration records the duration of kvstore operations
	KVStoreOperationsDuration metric.Vec[metric.Observer]

	// KVStoreEventsQueueDuration records the duration in seconds of time
	// received event was blocked before it could be queued
	KVStoreEventsQueueDuration metric.Vec[metric.Observer]

	// KVStoreQuorumErrors records the number of kvstore quorum errors
	KVStoreQuorumErrors metric.Vec[metric.Counter]

	// FQDNGarbageCollectorCleanedTotal is the number of domains cleaned by the
	// GC job.
	FQDNGarbageCollectorCleanedTotal metric.Counter

	// FQDNActiveNames is the number of domains inside the DNS cache that have
	// not expired (by TTL), per endpoint.
	FQDNActiveNames metric.Vec[metric.Gauge]

	// FQDNActiveIPs is the number of IPs inside the DNS cache associated with
	// a domain that has not expired (by TTL) and are currently active, per
	// endpoint.
	FQDNActiveIPs metric.Vec[metric.Gauge]

	// FQDNAliveZombieConnections is the number IPs associated with domains
	// that have expired (by TTL) yet still associated with an active
	// connection (aka zombie), per endpoint.
	FQDNAliveZombieConnections metric.Vec[metric.Gauge]

	// FQDNSemaphoreRejectedTotal is the total number of DNS requests rejected
	// by the DNS proxy because too many requests were in flight, as enforced by
	// the admission semaphore.
	FQDNSemaphoreRejectedTotal metric.Counter

	// IPCacheErrorsTotal is the total number of IPCache events handled in
	// the IPCache subsystem that resulted in errors.
	IPCacheErrorsTotal metric.Vec[metric.Counter]

	// IPCacheEventsTotal is the total number of IPCache events handled in
	// the IPCache subsystem.
	IPCacheEventsTotal metric.Vec[metric.Counter]

	// BPFSyscallDuration is the metric for bpf syscalls duration.
	BPFSyscallDuration metric.Vec[metric.Observer]

	// BPFMapOps is the metric to measure the number of operations done to a
	// bpf map.
	BPFMapOps metric.Vec[metric.Counter]

	// TriggerPolicyUpdateTotal is the metric to count total number of
	// policy update triggers
	TriggerPolicyUpdateTotal metric.Vec[metric.Counter]

	// TriggerPolicyUpdateFolds is the current level folding that is
	// happening when running policy update triggers
	TriggerPolicyUpdateFolds metric.Gauge

	// TriggerPolicyUpdateCallDuration measures the latency and call
	// duration of policy update triggers
	TriggerPolicyUpdateCallDuration metric.Vec[metric.Observer]

	// VersionMetric labelled by Cilium version
	VersionMetric metric.Vec[metric.Gauge]

	// ArpingRequestsTotal is the counter of the number of sent
	// (successful and failed) arping requests
	ArpingRequestsTotal metric.Vec[metric.Counter]

	// NodeEventsReceived is the prometheus metric to track the number of
	// node events received
	NodeEventsReceived metric.Vec[metric.Counter]

	// NumNodes is the prometheus metric to track the number of nodes
	// being managed
	NumNodes metric.Gauge

	// DatapathValidations is the prometheus metric to track the
	// number of datapath node validation calls
	DatapathValidations metric.Counter

	// TotalRemoteClusters is gauge metric keeping track of total number
	// of remote clusters.
	TotalRemoteClusters metric.Vec[metric.Gauge]

	// LastFailureTimestamp is a gauge metric tracking the last failure timestamp
	LastFailureTimestamp metric.Vec[metric.Gauge]

	// ReadinessStatus is a gauge metric tracking the readiness status of a remote cluster
	ReadinessStatus metric.Vec[metric.Gauge]

	// TotalFailures is a gauge metric tracking the number of failures when connecting to a remote cluster
	TotalFailures metric.Vec[metric.Gauge]

	// TotalNodes is a gauge metric tracking the number of total nodes in a remote cluster
	TotalNodes metric.Vec[metric.Gauge]

	// TotalGlobalServices is the gauge metric for total of global services
	TotalGlobalServices metric.Vec[metric.Gauge]

	// APILimiterWaitDuration is the gauge of the current mean, min, and
	// max wait duration
	APILimiterWaitDuration metric.Vec[metric.Gauge]

	// APILimiterProcessingDuration is the gauge of the mean and estimated
	// processing duration
	APILimiterProcessingDuration metric.Vec[metric.Gauge]

	// APILimiterRequestsInFlight is the gauge of the current and max
	// requests in flight
	APILimiterRequestsInFlight metric.Vec[metric.Gauge]

	// APILimiterRateLimit is the gauge of the current rate limiting
	// configuration including limit and burst
	APILimiterRateLimit metric.Vec[metric.Gauge]

	// APILimiterWaitHistoryDuration is a histogram that measures the
	// individual wait durations of API limiters
	APILimiterWaitHistoryDuration metric.Vec[metric.Observer]

	// APILimiterAdjustmentFactor is the gauge representing the latest
	// adjustment factor that was applied
	APILimiterAdjustmentFactor metric.Vec[metric.Gauge]

	// APILimiterProcessedRequests is the counter of the number of
	// processed (successful and failed) requests
	APILimiterProcessedRequests metric.Vec[metric.Counter]
}

func NewLegacyMetrics() *LegacyMetrics {
	legacyMetrics := &LegacyMetrics{
		// BootstrapTimes is the durations of cilium-agent bootstrap sequence.
		BootstrapTimes: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemAgent,
			Name:             "bootstrap_seconds",
			Help:             "Duration of bootstrap sequence",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelScope, LabelOutcome}),

		APIInteractions: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemAgent,
			Name:             "api_process_time_seconds",
			Help:             "Duration of processed API calls labeled by path, method and return code.",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelPath, LabelMethod, LabelAPIReturnCode}),

		EndpointRegenerationTotal: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Name:             "endpoint_regenerations_total",
			Help:             "Count of all endpoint regenerations that have completed, tagged by outcome",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{
			metric.LabelDescription{
				Name: "outcome",
				// TODO add description and known values
			},
		}),

		EndpointStateCount: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace:        Namespace,
			Name:             "endpoint_state",
			Help:             "Count of all endpoints, tagged by different endpoint states",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{
			metric.LabelDescription{
				Name: "endpoint_state",
				// TODO add description and known values
			},
		}),

		EndpointRegenerationTimeStats: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace:        Namespace,
			Name:             "endpoint_regeneration_time_stats_seconds",
			Help:             "Endpoint regeneration time stats labeled by the scope",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelScope, LabelStatus}),

		Policy: metric.NewGauge(metric.GaugeOpts{
			Namespace:        Namespace,
			Name:             "policy",
			Help:             "Number of policies currently loaded",
			EnabledByDefault: true,
		}),

		PolicyRegenerationCount: metric.NewCounter(metric.CounterOpts{
			Namespace:        Namespace,
			Name:             "policy_regeneration_total",
			Help:             "Total number of successful policy regenerations",
			EnabledByDefault: true,
		}),

		PolicyRegenerationTimeStats: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace:        Namespace,
			Name:             "policy_regeneration_time_stats_seconds",
			Help:             "Policy regeneration time stats labeled by the scope",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelScope, LabelStatus}),

		PolicyRevision: metric.NewGauge(metric.GaugeOpts{
			Namespace:        Namespace,
			Name:             "policy_max_revision",
			Help:             "Highest policy revision number in the agent",
			EnabledByDefault: true,
		}),

		PolicyImportErrorsTotal: metric.NewCounter(metric.CounterOpts{
			Namespace:        Namespace,
			Name:             "policy_import_errors_total",
			Help:             "Number of times a policy import has failed",
			EnabledByDefault: true,
		}),

		PolicyChangeTotal: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Name:             "policy_change_total",
			Help:             "Number of policy changes by outcome",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{{Name: "outcome"}}),

		PolicyEndpointStatus: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace:        Namespace,
			Name:             "policy_endpoint_enforcement_status",
			Help:             "Number of endpoints labeled by policy enforcement status",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelPolicyEnforcement}),

		PolicyImplementationDelay: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace:        Namespace,
			Name:             "policy_implementation_delay",
			Help:             "Time between a policy change and it being fully deployed into the datapath",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelPolicySource}),

		Identity: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace:        Namespace,
			Name:             "identity",
			Help:             "Number of identities currently allocated",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelType}),

		EventTS: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace:        Namespace,
			Name:             "event_ts",
			Help:             "Last timestamp when we received an event",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelEventSource, LabelScope, LabelAction}),

		EventLagK8s: metric.NewGauge(metric.GaugeOpts{
			Namespace: Namespace,
			Name:      "k8s_event_lag_seconds",
			Help:      "Lag for Kubernetes events - computed value between receiving a CNI ADD event from kubelet and a Pod event received from kube-api-server",
			ConstLabels: metric.ConstLabels{
				// TODO refine this situation
				metric.ConstLabel{
					Name: "source",
				}: LabelEventSourceK8s.Name,
			},
			EnabledByDefault: true,
		}),

		ProxyRedirects: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemPolicyL7,
			Name:             "proxy_redirects",
			Help:             "Number of redirects installed for endpoints, labeled by protocol",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelProtocolL7}),

		ProxyPolicyL7Total: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemPolicyL7,
			Name:             "policy_l7_total",
			Help:             "Number of total proxy requests handled",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{{
			Name: "rule",
			// TODO add description
		}}),

		ProxyParseErrors: metric.NewCounter(metric.CounterOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemPolicyL7,
			Name:             "policy_l7_parse_errors_total",
			Help:             "Number of total L7 parse errors",
			EnabledByDefault: true,
		}),

		ProxyForwarded: metric.NewCounter(metric.CounterOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemPolicyL7,
			Name:             "policy_l7_forwarded_total",
			Help:             "Number of total L7 forwarded requests/responses",
			EnabledByDefault: true,
		}),

		ProxyDenied: metric.NewCounter(metric.CounterOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemPolicyL7,
			Name:             "policy_l7_denied_total",
			Help:             "Number of total L7 denied requests/responses due to policy",
			EnabledByDefault: true,
		}),

		ProxyReceived: metric.NewCounter(metric.CounterOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemPolicyL7,
			Name:             "policy_l7_received_total",
			Help:             "Number of total L7 received requests/responses",
			EnabledByDefault: true,
		}),

		ProxyUpstreamTime: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace:        Namespace,
			Name:             "proxy_upstream_reply_seconds",
			Help:             "Seconds waited to get a reply from a upstream server",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{
			{Name: "error"},
			LabelProtocolL7,
			LabelScope,
		}),

		ProxyDatapathUpdateTimeout: metric.NewCounter(metric.CounterOpts{
			Namespace:        Namespace,
			Name:             "proxy_datapath_update_timeout_total",
			Help:             "Number of total datapath update timeouts due to FQDN IP updates",
			EnabledByDefault: false,
		}),

		DropCount: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Name:             "drop_count_total",
			Help:             "Total dropped packets, tagged by drop reason and ingress/egress direction",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{
			{Name: "reason"}, // TODO add description
			LabelDirection,
		}),

		DropBytes: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Name:             "drop_bytes_total",
			Help:             "Total dropped bytes, tagged by drop reason and ingress/egress direction",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{
			{Name: "reason"}, // TODO add description
			LabelDirection,
		}),

		ForwardCount: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Name:             "forward_count_total",
			Help:             "Total forwarded packets, tagged by ingress/egress direction",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelDirection}),

		ForwardBytes: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Name:             "forward_bytes_total",
			Help:             "Total forwarded bytes, tagged by ingress/egress direction",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelDirection}),

		ConntrackGCRuns: metric.NewCounterVec(metric.CounterOpts{
			Namespace: Namespace,
			Subsystem: SubsystemDatapath,
			Name:      "conntrack_gc_runs_total",
			Help: "Number of times that the conntrack garbage collector process was run " +
				"labeled by completion status",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelDatapathFamily, LabelProtocol, LabelStatus}),

		ConntrackGCKeyFallbacks: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemDatapath,
			Name:             "conntrack_gc_key_fallbacks_total",
			Help:             "Number of times a key fallback was needed when iterating over the BPF map",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelDatapathFamily, LabelProtocol}),

		ConntrackGCSize: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: Namespace,
			Subsystem: SubsystemDatapath,
			Name:      "conntrack_gc_entries",
			Help: "The number of alive and deleted conntrack entries at the end " +
				"of a garbage collector run labeled by datapath family.",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelDatapathFamily, LabelProtocol, LabelStatus}),

		NatGCSize: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: Namespace,
			Subsystem: SubsystemDatapath,
			Name:      "nat_gc_entries",
			Help: "The number of alive and deleted nat entries at the end " +
				"of a garbage collector run labeled by datapath family.",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelDatapathFamily, LabelDirection, LabelStatus}),

		ConntrackGCDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: Namespace,
			Subsystem: SubsystemDatapath,
			Name:      "conntrack_gc_duration_seconds",
			Help: "Duration in seconds of the garbage collector process " +
				"labeled by datapath family and completion status",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelDatapathFamily, LabelProtocol, LabelStatus}),

		ConntrackDumpResets: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemDatapath,
			Name:             "conntrack_dump_resets_total",
			Help:             "Number of conntrack dump resets. Happens when a BPF entry gets removed while dumping the map is in progress",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelDatapathArea, LabelDatapathName, LabelDatapathFamily}),

		SignalsHandled: metric.NewCounterVec(metric.CounterOpts{
			Namespace: Namespace,
			Subsystem: SubsystemDatapath,
			Name:      "signals_handled_total",
			Help: "Number of times that the datapath signal handler process was run " +
				"labeled by signal type, data and completion status",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelSignalType, LabelSignalData, LabelStatus}),

		ServicesCount: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Name:             "services_events_total",
			Help:             "Number of services events labeled by action type",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelAction}),

		ControllerRuns: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Name:             "controllers_runs_total",
			Help:             "Number of times that a controller process was run labeled by completion status",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelStatus}),

		ControllerRunsDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace:        Namespace,
			Name:             "controllers_runs_duration_seconds",
			Help:             "Duration in seconds of the controller process labeled by completion status",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelStatus}),

		SubprocessStart: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Name:             "subprocess_start_total",
			Help:             "Number of times that Cilium has started a subprocess, labeled by subsystem",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelSubsystem}),

		KubernetesEventProcessed: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Name:             "kubernetes_events_total",
			Help:             "Number of Kubernetes events processed labeled by scope, action and execution result",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelScope, LabelAction, LabelStatus}),

		KubernetesEventReceived: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Name:             "kubernetes_events_received_total",
			Help:             "Number of Kubernetes events received labeled by scope, action, valid data and equalness",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{
			LabelScope,
			LabelAction,
			{Name: "valid"},
			{Name: "equal"},
		}),

		KubernetesAPIInteractions: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemK8sClient,
			Name:             "api_latency_time_seconds",
			Help:             "Duration of processed API calls labeled by path and method.",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelPath, LabelMethod}),

		KubernetesAPICallsTotal: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemK8sClient,
			Name:             "api_calls_total",
			Help:             "Number of API calls made to kube-apiserver labeled by host, method and return code.",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{
			{Name: "host"},
			LabelMethod,
			LabelAPIReturnCode,
		}),

		KubernetesCNPStatusCompletion: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemK8s,
			Name:             "cnp_status_completion_seconds",
			Help:             "Duration in seconds in how long it took to complete a CNP status update",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelAttempts, LabelOutcome}),

		TerminatingEndpointsEvents: metric.NewCounter(metric.CounterOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemK8s,
			Name:             "terminating_endpoints_events_total",
			Help:             "Number of terminating endpoint events received from Kubernetes",
			EnabledByDefault: true,
		}),

		IpamEvent: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Name:             "ipam_events_total",
			Help:             "Number of IPAM events received labeled by action and datapath family type",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelAction, LabelDatapathFamily}),

		KVStoreOperationsDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemKVStore,
			Name:             "operations_duration_seconds",
			Help:             "Duration in seconds of kvstore operations",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelScope, LabelKind, LabelAction, LabelOutcome}),

		KVStoreEventsQueueDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemKVStore,
			Name:             "events_queue_seconds",
			Help:             "Duration in seconds of time received event was blocked before it could be queued",
			Buckets:          []float64{.002, .005, .01, .015, .025, .05, .1, .25, .5, .75, 1},
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelScope, LabelAction}),

		KVStoreQuorumErrors: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemKVStore,
			Name:             "quorum_errors_total",
			Help:             "Number of quorum errors",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelError}),

		IPCacheErrorsTotal: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemIPCache,
			Name:             "errors_total",
			Help:             "Number of errors interacting with the IP to Identity cache",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelType, LabelError}),

		IPCacheEventsTotal: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemIPCache,
			Name:             "events_total",
			Help:             "Number of events interacting with the IP to Identity cache",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelType}),

		FQDNGarbageCollectorCleanedTotal: metric.NewCounter(metric.CounterOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemFQDN,
			Name:             "gc_deletions_total",
			Help:             "Number of FQDNs that have been cleaned on FQDN Garbage collector job",
			EnabledByDefault: true,
		}),

		FQDNActiveNames: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemFQDN,
			Name:             "active_names",
			Help:             "Number of domains inside the DNS cache that have not expired (by TTL), per endpoint",
			EnabledByDefault: false,
		}, metric.LabelDescriptions{LabelPeerEndpoint}),

		FQDNActiveIPs: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemFQDN,
			Name:             "active_ips",
			Help:             "Number of IPs inside the DNS cache associated with a domain that has not expired (by TTL), per endpoint",
			EnabledByDefault: false,
		}, metric.LabelDescriptions{LabelPeerEndpoint}),

		FQDNAliveZombieConnections: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemFQDN,
			Name:             "alive_zombie_connections",
			Help:             "Number of IPs associated with domains that have expired (by TTL) yet still associated with an active connection (aka zombie), per endpoint",
			EnabledByDefault: false,
		}, metric.LabelDescriptions{LabelPeerEndpoint}),

		FQDNSemaphoreRejectedTotal: metric.NewCounter(metric.CounterOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemFQDN,
			Name:             "semaphore_rejected_total",
			Help:             "Number of DNS request rejected by the DNS Proxy's admission semaphore",
			EnabledByDefault: false,
		}),

		BPFSyscallDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemBPF,
			Name:             "syscall_duration_seconds",
			Help:             "Duration of BPF system calls",
			EnabledByDefault: false,
		}, metric.LabelDescriptions{LabelOperation, LabelOutcome}),

		BPFMapOps: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemBPF,
			Name:             "map_ops_total",
			Help:             "Total operations on map, tagged by map name",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelMapName, LabelOperation, LabelOutcome}),

		TriggerPolicyUpdateTotal: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemTriggers,
			Name:             "policy_update_total",
			Help:             "Total number of policy update trigger invocations labeled by reason",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{{Name: "reason"}}),

		TriggerPolicyUpdateFolds: metric.NewGauge(metric.GaugeOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemTriggers,
			Name:             "policy_update_folds",
			Help:             "Current number of folds",
			EnabledByDefault: true,
		}),

		TriggerPolicyUpdateCallDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemTriggers,
			Name:             "policy_update_call_duration_seconds",
			Help:             "Duration of policy update trigger",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelType}),

		VersionMetric: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace:        Namespace,
			Name:             "version",
			Help:             "Cilium version",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelVersion}),

		ArpingRequestsTotal: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemNodeNeigh,
			Name:             "arping_requests_total",
			Help:             "Number of arping requests sent labeled by status",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelStatus}),

		EndpointPropagationDelay: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace:        Namespace,
			Name:             "endpoint_propagation_delay_seconds",
			Help:             "CiliumEndpoint roundtrip propagation delay in seconds",
			Buckets:          []float64{.05, .1, 1, 5, 30, 60, 120, 240, 300, 600},
			EnabledByDefault: true,
		}, metric.LabelDescriptions{}),

		NodeConnectivityStatus: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace:        Namespace,
			Name:             "node_connectivity_status",
			Help:             "The last observed status of both ICMP and HTTP connectivity between the current Cilium agent and other Cilium nodes",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{
			LabelSourceCluster,
			LabelSourceNodeName,
			LabelTargetCluster,
			LabelTargetNodeName,
			LabelTargetNodeType,
			LabelType,
		}),

		NodeConnectivityLatency: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace:        Namespace,
			Name:             "node_connectivity_latency_seconds",
			Help:             "The last observed latency between the current Cilium agent and other Cilium nodes in seconds",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{
			LabelSourceCluster,
			LabelSourceNodeName,
			LabelTargetCluster,
			LabelTargetNodeName,
			LabelTargetNodeIP,
			LabelTargetNodeType,
			LabelType,
			LabelProtocol,
			LabelAddressType,
		}),

		NodeEventsReceived: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemNodes,
			Name:             "all_events_received_total",
			Help:             "Number of node events received",
			EnabledByDefault: true,
		}, []metric.LabelDescription{
			{Name: "event_type"},
			{Name: "source"},
		}),

		NumNodes: metric.NewGauge(metric.GaugeOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemNodes,
			Name:             "all_num",
			Help:             "Number of nodes managed",
			EnabledByDefault: true,
		}),

		DatapathValidations: metric.NewCounter(metric.CounterOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemNodes,
			Name:             "all_datapath_validations_total",
			Help:             "Number of validation calls to implement the datapath implementation of a node",
			EnabledByDefault: true,
		}),

		TotalRemoteClusters: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: Namespace,
			Subsystem: SubsystemClustermesh,
			Name:      "remote_clusters",
			Help:      "The total number of remote clusters meshed with the local cluster",
		}, []metric.LabelDescription{LabelSourceCluster, LabelSourceNodeName}),

		LastFailureTimestamp: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: Namespace,
			Subsystem: SubsystemClustermesh,
			Name:      "remote_cluster_last_failure_ts",
			Help:      "The timestamp of the last failure of the remote cluster",
		}, []metric.LabelDescription{LabelSourceCluster, LabelSourceNodeName, LabelTargetCluster}),

		ReadinessStatus: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: Namespace,
			Subsystem: SubsystemClustermesh,
			Name:      "remote_cluster_readiness_status",
			Help:      "The readiness status of the remote cluster",
		}, []metric.LabelDescription{LabelSourceCluster, LabelSourceNodeName, LabelTargetCluster}),

		TotalFailures: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: Namespace,
			Subsystem: SubsystemClustermesh,
			Name:      "remote_cluster_failures",
			Help:      "The total number of failures related to the remote cluster",
		}, []metric.LabelDescription{LabelSourceCluster, LabelSourceNodeName, LabelTargetCluster}),

		TotalNodes: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: Namespace,
			Subsystem: SubsystemClustermesh,
			Name:      "remote_cluster_nodes",
			Help:      "The total number of nodes in the remote cluster",
		}, []metric.LabelDescription{LabelSourceCluster, LabelSourceNodeName, LabelTargetCluster}),

		TotalGlobalServices: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: Namespace,
			Subsystem: SubsystemClustermesh,
			Name:      "global_services",
			Help:      "The total number of global services in the cluster mesh",
		}, []metric.LabelDescription{LabelSourceCluster, LabelSourceNodeName}),

		APILimiterWaitHistoryDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemAPILimiter,
			Name:             "wait_history_duration_seconds",
			Help:             "Histogram over duration of waiting period for API calls subjects to rate limiting",
			EnabledByDefault: false,
		}, metric.LabelDescriptions{{Name: "api_call"}}),

		APILimiterWaitDuration: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemAPILimiter,
			Name:             "wait_duration_seconds",
			Help:             "Current wait time for api calls",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{
			{Name: "api_call"},
			{Name: "value"},
		}),

		APILimiterProcessingDuration: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemAPILimiter,
			Name:             "processing_duration_seconds",
			Help:             "Current processing time of api call",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{
			{Name: "api_call"},
			{Name: "value"},
		}),

		APILimiterRequestsInFlight: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemAPILimiter,
			Name:             "requests_in_flight",
			Help:             "Current requests in flight",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{
			{Name: "api_call"},
			{Name: "value"},
		}),

		APILimiterRateLimit: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemAPILimiter,
			Name:             "rate_limit",
			Help:             "Current rate limiting configuration",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{
			{Name: "api_call"},
			{Name: "value"},
		}),

		APILimiterAdjustmentFactor: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemAPILimiter,
			Name:             "adjustment_factor",
			Help:             "Current adjustment factor while auto adjusting",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{
			{Name: "api_call"},
		}),

		APILimiterProcessedRequests: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemAPILimiter,
			Name:             "processed_requests_total",
			Help:             "Total number of API requests processed",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{
			{Name: "api_call"},
			LabelOutcome,
		}),
	}

	BootstrapTimes = legacyMetrics.BootstrapTimes
	APIInteractions = legacyMetrics.APIInteractions
	NodeConnectivityStatus = legacyMetrics.NodeConnectivityStatus
	NodeConnectivityLatency = legacyMetrics.NodeConnectivityLatency
	Endpoint = legacyMetrics.Endpoint
	EndpointRegenerationTotal = legacyMetrics.EndpointRegenerationTotal
	EndpointStateCount = legacyMetrics.EndpointStateCount
	EndpointRegenerationTimeStats = legacyMetrics.EndpointRegenerationTimeStats
	EndpointPropagationDelay = legacyMetrics.EndpointPropagationDelay
	Policy = legacyMetrics.Policy
	PolicyRegenerationCount = legacyMetrics.PolicyRegenerationCount
	PolicyRegenerationTimeStats = legacyMetrics.PolicyRegenerationTimeStats
	PolicyRevision = legacyMetrics.PolicyRevision
	PolicyImportErrorsTotal = legacyMetrics.PolicyImportErrorsTotal
	PolicyChangeTotal = legacyMetrics.PolicyChangeTotal
	PolicyEndpointStatus = legacyMetrics.PolicyEndpointStatus
	PolicyImplementationDelay = legacyMetrics.PolicyImplementationDelay
	Identity = legacyMetrics.Identity
	EventTS = legacyMetrics.EventTS
	EventLagK8s = legacyMetrics.EventLagK8s
	ProxyRedirects = legacyMetrics.ProxyRedirects
	ProxyPolicyL7Total = legacyMetrics.ProxyPolicyL7Total
	ProxyParseErrors = legacyMetrics.ProxyParseErrors
	ProxyForwarded = legacyMetrics.ProxyForwarded
	ProxyDenied = legacyMetrics.ProxyDenied
	ProxyReceived = legacyMetrics.ProxyReceived
	ProxyUpstreamTime = legacyMetrics.ProxyUpstreamTime
	ProxyDatapathUpdateTimeout = legacyMetrics.ProxyDatapathUpdateTimeout
	DropCount = legacyMetrics.DropCount
	DropBytes = legacyMetrics.DropBytes
	ForwardCount = legacyMetrics.ForwardCount
	ForwardBytes = legacyMetrics.ForwardBytes
	ConntrackGCRuns = legacyMetrics.ConntrackGCRuns
	ConntrackGCKeyFallbacks = legacyMetrics.ConntrackGCKeyFallbacks
	ConntrackGCSize = legacyMetrics.ConntrackGCSize
	NatGCSize = legacyMetrics.NatGCSize
	ConntrackGCDuration = legacyMetrics.ConntrackGCDuration
	ConntrackDumpResets = legacyMetrics.ConntrackDumpResets
	SignalsHandled = legacyMetrics.SignalsHandled
	ServicesCount = legacyMetrics.ServicesCount
	ControllerRuns = legacyMetrics.ControllerRuns
	ControllerRunsDuration = legacyMetrics.ControllerRunsDuration
	SubprocessStart = legacyMetrics.SubprocessStart
	KubernetesEventProcessed = legacyMetrics.KubernetesEventProcessed
	KubernetesEventReceived = legacyMetrics.KubernetesEventReceived
	KubernetesAPIInteractions = legacyMetrics.KubernetesAPIInteractions
	KubernetesAPICallsTotal = legacyMetrics.KubernetesAPICallsTotal
	KubernetesCNPStatusCompletion = legacyMetrics.KubernetesCNPStatusCompletion
	TerminatingEndpointsEvents = legacyMetrics.TerminatingEndpointsEvents
	IpamEvent = legacyMetrics.IpamEvent
	KVStoreOperationsDuration = legacyMetrics.KVStoreOperationsDuration
	KVStoreEventsQueueDuration = legacyMetrics.KVStoreEventsQueueDuration
	KVStoreQuorumErrors = legacyMetrics.KVStoreQuorumErrors
	FQDNGarbageCollectorCleanedTotal = legacyMetrics.FQDNGarbageCollectorCleanedTotal
	FQDNActiveNames = legacyMetrics.FQDNActiveNames
	FQDNActiveIPs = legacyMetrics.FQDNActiveIPs
	FQDNAliveZombieConnections = legacyMetrics.FQDNAliveZombieConnections
	FQDNSemaphoreRejectedTotal = legacyMetrics.FQDNSemaphoreRejectedTotal
	IPCacheErrorsTotal = legacyMetrics.IPCacheErrorsTotal
	IPCacheEventsTotal = legacyMetrics.IPCacheEventsTotal
	BPFSyscallDuration = legacyMetrics.BPFSyscallDuration
	BPFMapOps = legacyMetrics.BPFMapOps
	TriggerPolicyUpdateTotal = legacyMetrics.TriggerPolicyUpdateTotal
	TriggerPolicyUpdateFolds = legacyMetrics.TriggerPolicyUpdateFolds
	TriggerPolicyUpdateCallDuration = legacyMetrics.TriggerPolicyUpdateCallDuration
	VersionMetric = legacyMetrics.VersionMetric
	ArpingRequestsTotal = legacyMetrics.ArpingRequestsTotal
	NodeEventsReceived = legacyMetrics.NodeEventsReceived
	NumNodes = legacyMetrics.NumNodes
	DatapathValidations = legacyMetrics.DatapathValidations
	TotalRemoteClusters = legacyMetrics.TotalRemoteClusters
	LastFailureTimestamp = legacyMetrics.LastFailureTimestamp
	ReadinessStatus = legacyMetrics.ReadinessStatus
	TotalFailures = legacyMetrics.TotalFailures
	TotalNodes = legacyMetrics.TotalNodes
	TotalGlobalServices = legacyMetrics.TotalGlobalServices
	APILimiterWaitDuration = legacyMetrics.APILimiterWaitDuration
	APILimiterProcessingDuration = legacyMetrics.APILimiterProcessingDuration
	APILimiterRequestsInFlight = legacyMetrics.APILimiterRequestsInFlight
	APILimiterRateLimit = legacyMetrics.APILimiterRateLimit
	APILimiterWaitHistoryDuration = legacyMetrics.APILimiterWaitHistoryDuration
	APILimiterAdjustmentFactor = legacyMetrics.APILimiterAdjustmentFactor
	APILimiterProcessedRequests = legacyMetrics.APILimiterProcessedRequests

	return legacyMetrics
}

// GaugeWithThreshold is a prometheus gauge that registers itself with
// prometheus if over a threshold value and unregisters when under.
type GaugeWithThreshold struct {
	gaugeVec  metric.DeletableVec[metric.Gauge]
	labels    prometheus.Labels
	threshold float64
	gauge     metric.Gauge
}

// Set the value of the GaugeWithThreshold.
func (gwt *GaugeWithThreshold) Set(value float64) {
	overThreshold := value > gwt.threshold
	if gwt.gauge == nil {
		if !overThreshold {
			return
		}

		gwt.gauge = gwt.gaugeVec.With(gwt.labels)
		gwt.gauge.Set(value)
		return
	}

	if !overThreshold {
		gwt.gaugeVec.Delete(gwt.labels)
		gwt.gauge = nil
		return
	}

	gwt.gauge.Set(value)
}

func (gwt *GaugeWithThreshold) Get() float64 {
	if gwt.gauge == nil {
		return 0
	}

	return gwt.gauge.Get()
}

type MapPressureMetric struct {
	MapPressure metric.DeletableVec[metric.Gauge]
}

var MapPressure *MapPressureMetric

func NewMapPressureMetric() MapPressureMetric {
	mapPressureMetric := MapPressureMetric{
		MapPressure: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace:        Namespace,
			Subsystem:        SubsystemBPF,
			Name:             "map_pressure",
			Help:             "Fill percentage of map, tagged by map name",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{LabelMapName}),
	}

	MapPressure = &mapPressureMetric

	return mapPressureMetric
}

// NewBPFMapPressureGauge creates a new GaugeWithThreshold for the
// cilium_bpf_map_pressure metric with the map name as constant label.
func (mpm *MapPressureMetric) BPFMapPressureGauge(mapname string, threshold float64) *GaugeWithThreshold {
	return &GaugeWithThreshold{
		gaugeVec:  mpm.MapPressure,
		labels:    prometheus.Labels{LabelMapName.Name: mapname},
		threshold: threshold,
	}
}

func (mpm *MapPressureMetric) IsEnabled() bool {
	return mpm != nil && mpm.MapPressure.IsEnabled()
}

// Error2Outcome converts an error to LabelOutcome
func Error2Outcome(err error) string {
	if err != nil {
		return LabelValueOutcomeFail.Name
	}

	return LabelValueOutcomeSuccess.Name
}

func BoolToFloat64(v bool) float64 {
	if v {
		return 1
	}
	return 0
}
