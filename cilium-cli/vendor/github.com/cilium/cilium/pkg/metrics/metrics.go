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
	"net/http"
	"regexp"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/version"
)

const (
	// ErrorTimeout is the value used to notify timeout errors.
	ErrorTimeout = "timeout"

	// ErrorProxy is the value used to notify errors on Proxy.
	ErrorProxy = "proxy"

	// L7DNS is the value used to report DNS label on metrics
	L7DNS = "dns"

	// SubsystemBPF is the subsystem to scope metrics related to the bpf syscalls.
	SubsystemBPF = "bpf"

	// SubsystemDatapath is the subsystem to scope metrics related to management of
	// the datapath. It is prepended to metric names and separated with a '_'.
	SubsystemDatapath = "datapath"

	// SubsystemAgent is the subsystem to scope metrics related to the cilium agent itself.
	SubsystemAgent = "agent"

	// SubsystemFQDN is the subsystem to scope metrics related to the FQDN proxy.
	SubsystemIPCache = "ipcache"

	// SubsystemK8s is the subsystem to scope metrics related to Kubernetes
	SubsystemK8s = "k8s"

	// SubsystemK8sClient is the subsystem to scope metrics related to the kubernetes client.
	SubsystemK8sClient = "k8s_client"

	// SubsystemKVStore is the subsystem to scope metrics related to the kvstore.
	SubsystemKVStore = "kvstore"

	// SubsystemFQDN is the subsystem to scope metrics related to the FQDN proxy.
	SubsystemFQDN = "fqdn"

	// SubsystemNodes is the subsystem to scope metrics related to the node manager.
	SubsystemNodes = "nodes"

	// SubsystemTriggers is the subsystem to scope metrics related to the trigger package.
	SubsystemTriggers = "triggers"

	// SubsystemAPILimiter is the subsystem to scope metrics related to the API limiter package.
	SubsystemAPILimiter = "api_limiter"

	// Namespace is used to scope metrics from cilium. It is prepended to metric
	// names and separated with a '_'
	Namespace = "cilium"

	// LabelError indicates the type of error (string)
	LabelError = "error"

	// LabelOutcome indicates whether the outcome of the operation was successful or not
	LabelOutcome = "outcome"

	// LabelAttempts is the number of attempts it took to complete the operation
	LabelAttempts = "attempts"

	// Labels

	// LabelValueOutcomeSuccess is used as a successful outcome of an operation
	LabelValueOutcomeSuccess = "success"

	// LabelValueOutcomeFail is used as an unsuccessful outcome of an operation
	LabelValueOutcomeFail = "fail"

	// LabelEventSourceAPI marks event-related metrics that come from the API
	LabelEventSourceAPI = "api"

	// LabelEventSourceK8s marks event-related metrics that come from k8s
	LabelEventSourceK8s = "k8s"

	// LabelEventSourceFQDN marks event-related metrics that come from pkg/fqdn
	LabelEventSourceFQDN = "fqdn"

	// LabelEventSourceContainerd marks event-related metrics that come from docker
	LabelEventSourceContainerd = "docker"

	// LabelDatapathArea marks which area the metrics are related to (eg, which BPF map)
	LabelDatapathArea = "area"

	// LabelDatapathName marks a unique identifier for this metric.
	// The name should be defined once for a given type of error.
	LabelDatapathName = "name"

	// LabelDatapathFamily marks which protocol family (IPv4, IPV6) the metric is related to.
	LabelDatapathFamily = "family"

	// LabelProtocol marks the L4 protocol (TCP, ANY) for the metric.
	LabelProtocol = "protocol"

	// LabelSignalType marks the signal name
	LabelSignalType = "signal"

	// LabelSignalData marks the signal data
	LabelSignalData = "data"

	// LabelStatus the label from completed task
	LabelStatus = "status"

	// LabelPolicyEnforcement is the label used to see the enforcement status
	LabelPolicyEnforcement = "enforcement"

	// LabelPolicySource is the label used to see the enforcement status
	LabelPolicySource = "source"

	// LabelScope is the label used to defined multiples scopes in the same
	// metric. For example, one counter may measure a metric over the scope of
	// the entire event (scope=global), or just part of an event
	// (scope=slow_path)
	LabelScope = "scope"

	// LabelProtocolL7 is the label used when working with layer 7 protocols.
	LabelProtocolL7 = "protocol_l7"

	// LabelBuildState is the state a build queue entry is in
	LabelBuildState = "state"

	// LabelBuildQueueName is the name of the build queue
	LabelBuildQueueName = "name"

	// LabelAction is the label used to defined what kind of action was performed in a metric
	LabelAction = "action"

	// LabelSubsystem is the label used to refer to any of the child process
	// started by cilium (Envoy, monitor, etc..)
	LabelSubsystem = "subsystem"

	// LabelKind is the kind of a label
	LabelKind = "kind"

	// LabelEventSource is the source of a label for event metrics
	// i.e. k8s, containerd, api.
	LabelEventSource = "source"

	// LabelPath is the label for the API path
	LabelPath = "path"
	// LabelMethod is the label for the HTTP method
	LabelMethod = "method"

	// LabelAPIReturnCode is the HTTP code returned for that API path
	LabelAPIReturnCode = "return_code"

	// LabelOperation is the label for BPF maps operations
	LabelOperation = "operation"

	// LabelMapName is the label for the BPF map name
	LabelMapName = "map_name"

	// LabelVersion is the label for the version number
	LabelVersion = "version"

	// LabelVersionRevision is the label for the version revision
	LabelVersionRevision = "revision"

	// LabelArch is the label for the platform architecture (e.g. linux/amd64)
	LabelArch = "arch"

	// LabelDirection is the label for traffic direction
	LabelDirection = "direction"

	// LabelSourceCluster is the label for source cluster name
	LabelSourceCluster = "source_cluster"

	// LabelSourceNodeName is the label for source node name
	LabelSourceNodeName = "source_node_name"

	// LabelTargetCluster is the label for target cluster name
	LabelTargetCluster = "target_cluster"

	// LabelTargetNodeIP is the label for target node IP
	LabelTargetNodeIP = "target_node_ip"

	// LabelTargetNodeName is the label for target node name
	LabelTargetNodeName = "target_node_name"

	// LabelTargetNodeType is the label for target node type (local_node, remote_intra_cluster, vs remote_inter_cluster)
	LabelTargetNodeType = "target_node_type"

	LabelLocationLocalNode          = "local_node"
	LabelLocationRemoteIntraCluster = "remote_intra_cluster"
	LabelLocationRemoteInterCluster = "remote_inter_cluster"

	// LabelType is the label for type in general (e.g. endpoint, node)
	LabelType         = "type"
	LabelPeerEndpoint = "endpoint"
	LabelPeerNode     = "node"

	LabelTrafficHTTP = "http"
	LabelTrafficICMP = "icmp"

	LabelAddressType          = "address_type"
	LabelAddressTypePrimary   = "primary"
	LabelAddressTypeSecondary = "secondary"
)

var (
	// goCustomCollectorsRX tracks enabled go runtime metrics.
	goCustomCollectorsRX = regexp.MustCompile(`^/sched/latencies:seconds`)

	registry = prometheus.NewPedanticRegistry()

	// BootstrapTimes is the durations of cilium-agent bootstrap sequence.
	BootstrapTimes = NoOpObserverVec

	// APIInteractions is the total time taken to process an API call made
	// to the cilium-agent
	APIInteractions = NoOpObserverVec

	// Status

	// NodeConnectivityStatus is the connectivity status between local node to
	// other node intra or inter cluster.
	NodeConnectivityStatus = NoOpGaugeVec

	// NodeConnectivityLatency is the connectivity latency between local node to
	// other node intra or inter cluster.
	NodeConnectivityLatency = NoOpGaugeVec

	// Endpoint

	// Endpoint is a function used to collect this metric.
	// It must be thread-safe.
	Endpoint prometheus.GaugeFunc

	// EndpointRegenerationTotal is a count of the number of times any endpoint
	// has been regenerated and success/fail outcome
	EndpointRegenerationTotal = NoOpCounterVec

	// EndpointStateCount is the total count of the endpoints in various states.
	EndpointStateCount = NoOpGaugeVec

	// EndpointRegenerationTimeStats is the total time taken to regenerate
	// endpoints, labeled by span name and status ("success" or "failure")
	EndpointRegenerationTimeStats = NoOpObserverVec

	// EndpointPropagationDelay is the delay between creation of local CiliumEndpoint
	// and update for that CiliumEndpoint received through CiliumEndpointSlice.
	// Measure of local CEP roundtrip time with CiliumEndpointSlice feature enabled.
	EndpointPropagationDelay = NoOpObserverVec

	// Policy
	// Policy is the number of policies loaded into the agent
	Policy = NoOpGauge

	// PolicyRegenerationCount is the total number of successful policy
	// regenerations.
	PolicyRegenerationCount = NoOpCounter

	// PolicyRegenerationTimeStats is the total time taken to generate policies
	PolicyRegenerationTimeStats = NoOpObserverVec

	// PolicyRevision is the current policy revision number for this agent
	PolicyRevision = NoOpGauge

	// PolicyImportErrorsTotal is a count of failed policy imports.
	// This metric was deprecated in Cilium 1.14 and is to be removed in 1.15.
	// It is replaced by PolicyChangeTotal metric.
	PolicyImportErrorsTotal = NoOpCounter

	// PolicyChangeTotal is a count of policy changes by outcome ("success" or
	// "failure")
	PolicyChangeTotal = NoOpCounterVec

	// PolicyEndpointStatus is the number of endpoints with policy labeled by enforcement type
	PolicyEndpointStatus = NoOpGaugeVec

	// PolicyImplementationDelay is a distribution of times taken from adding a
	// policy (and incrementing the policy revision) to seeing it in the datapath
	// per Endpoint. This reflects the actual delay perceived by traffic flowing
	// through the datapath. The longest times will roughly correlate with the
	// time taken to fully deploy an endpoint.
	PolicyImplementationDelay = NoOpObserverVec

	// CIDRGroup

	// CIDRGroupTranslationTimeStats is the time taken to translate the policy field `FromCIDRGroupRef`
	// after the referenced CIDRGroups have been updated or deleted.
	CIDRGroupTranslationTimeStats = NoOpHistogram

	// CIDRGroupPolicies is the number of CNPs and CCNPs referencing at least one CiliumCIDRGroup.
	CIDRGroupPolicies = NoOpGauge

	// Identity

	// Identity is the number of identities currently in use on the node by type
	Identity = NoOpGaugeVec

	// Events

	// EventTS*is the time in seconds since epoch that we last received an
	// event that we will handle
	// source is one of k8s, docker or apia

	// EventTS is the timestamp of k8s resource events.
	EventTS = NoOpGaugeVec

	// EventLagK8s is the lag calculation for k8s Pod events.
	EventLagK8s = NoOpGauge

	// L7 statistics

	// ProxyRedirects is the number of redirects labeled by protocol
	ProxyRedirects = NoOpGaugeVec

	// ProxyPolicyL7Total is a count of all l7 requests handled by proxy
	ProxyPolicyL7Total = NoOpCounterVec

	// ProxyParseErrors is a count of failed parse errors on proxy
	// Deprecated: in favor of ProxyPolicyL7Total
	ProxyParseErrors = NoOpCounter

	// ProxyForwarded is a count of all forwarded requests by proxy
	// Deprecated: in favor of ProxyPolicyL7Total
	ProxyForwarded = NoOpCounter

	// ProxyDenied is a count of all denied requests by policy by the proxy
	// Deprecated: in favor of ProxyPolicyL7Total
	ProxyDenied = NoOpCounter

	// ProxyReceived is a count of all received requests by the proxy
	// Deprecated: in favor of ProxyPolicyL7Total
	ProxyReceived = NoOpCounter

	// ProxyUpstreamTime is how long the upstream server took to reply labeled
	// by error, protocol and span time
	ProxyUpstreamTime = NoOpObserverVec

	// ProxyDatapathUpdateTimeout is a count of all the timeouts encountered while
	// updating the datapath due to an FQDN IP update
	ProxyDatapathUpdateTimeout = NoOpCounter

	// L3-L4 statistics

	// DropCount is the total drop requests,
	// tagged by drop reason and direction(ingress/egress)
	DropCount = NoOpCounterVec

	// DropBytes is the total dropped bytes,
	// tagged by drop reason and direction(ingress/egress)
	DropBytes = NoOpCounterVec

	// ForwardCount is the total forwarded packets,
	// tagged by ingress/egress direction
	ForwardCount = NoOpCounterVec

	// ForwardBytes is the total forwarded bytes,
	// tagged by ingress/egress direction
	ForwardBytes = NoOpCounterVec

	// Datapath statistics

	// ConntrackGCRuns is the number of times that the conntrack GC
	// process was run.
	ConntrackGCRuns = NoOpCounterVec

	// ConntrackGCKeyFallbacks number of times that the conntrack key fallback was invalid.
	ConntrackGCKeyFallbacks = NoOpCounterVec

	// ConntrackGCSize the number of entries in the conntrack table
	ConntrackGCSize = NoOpGaugeVec

	// NatGCSize the number of entries in the nat table
	NatGCSize = NoOpGaugeVec

	// ConntrackGCDuration the duration of the conntrack GC process in milliseconds.
	ConntrackGCDuration = NoOpObserverVec

	// ConntrackDumpReset marks the count for conntrack dump resets
	ConntrackDumpResets = NoOpCounterVec

	// Signals

	// SignalsHandled is the number of signals received.
	SignalsHandled = NoOpCounterVec

	// Services

	// ServicesCount number of services
	ServicesCount = NoOpCounterVec

	// Errors and warnings

	// ErrorsWarnings is the number of errors and warnings in cilium-agent instances
	ErrorsWarnings = NoOpCounterVec

	// ControllerRuns is the number of times that a controller process runs.
	ControllerRuns = NoOpCounterVec

	// ControllerRunsDuration the duration of the controller process in seconds
	ControllerRunsDuration = NoOpObserverVec

	// subprocess, labeled by Subsystem
	SubprocessStart = NoOpCounterVec

	// Kubernetes Events

	// KubernetesEventProcessed is the number of Kubernetes events
	// processed labeled by scope, action and execution result
	KubernetesEventProcessed = NoOpCounterVec

	// KubernetesEventReceived is the number of Kubernetes events received
	// labeled by scope, action, valid data and equalness.
	KubernetesEventReceived = NoOpCounterVec

	// Kubernetes interactions

	// KubernetesAPIInteractions is the total time taken to process an API call made
	// to the kube-apiserver
	KubernetesAPIInteractions = NoOpObserverVec

	// KubernetesAPICallsTotal is the counter for all API calls made to
	// kube-apiserver.
	KubernetesAPICallsTotal = NoOpCounterVec

	// KubernetesCNPStatusCompletion is the number of seconds it takes to
	// complete a CNP status update
	KubernetesCNPStatusCompletion = NoOpObserverVec

	// TerminatingEndpointsEvents is the number of terminating endpoint events received from kubernetes.
	TerminatingEndpointsEvents = NoOpCounter

	// IPAM events

	// IpamEvent is the number of IPAM events received labeled by action and
	// datapath family type
	IpamEvent = NoOpCounterVec

	// KVstore events

	// KVStoreOperationsDuration records the duration of kvstore operations
	KVStoreOperationsDuration = NoOpObserverVec

	// KVStoreEventsQueueDuration records the duration in seconds of time
	// received event was blocked before it could be queued
	KVStoreEventsQueueDuration = NoOpObserverVec

	// KVStoreQuorumErrors records the number of kvstore quorum errors
	KVStoreQuorumErrors = NoOpCounterVec

	// FQDNGarbageCollectorCleanedTotal is the number of domains cleaned by the
	// GC job.
	FQDNGarbageCollectorCleanedTotal = NoOpCounter

	// FQDNActiveNames is the number of domains inside the DNS cache that have
	// not expired (by TTL), per endpoint.
	FQDNActiveNames = NoOpGaugeVec

	// FQDNActiveIPs is the number of IPs inside the DNS cache associated with
	// a domain that has not expired (by TTL) and are currently active, per
	// endpoint.
	FQDNActiveIPs = NoOpGaugeVec

	// FQDNAliveZombieConnections is the number IPs associated with domains
	// that have expired (by TTL) yet still associated with an active
	// connection (aka zombie), per endpoint.
	FQDNAliveZombieConnections = NoOpGaugeVec

	// FQDNSemaphoreRejectedTotal is the total number of DNS requests rejected
	// by the DNS proxy because too many requests were in flight, as enforced by
	// the admission semaphore.
	FQDNSemaphoreRejectedTotal = NoOpCounter

	// IPCacheErrorsTotal is the total number of IPCache events handled in
	// the IPCache subsystem that resulted in errors.
	IPCacheErrorsTotal = NoOpCounterVec

	// IPCacheEventsTotal is the total number of IPCache events handled in
	// the IPCache subsystem.
	IPCacheEventsTotal = NoOpCounterVec

	// BPFSyscallDuration is the metric for bpf syscalls duration.
	BPFSyscallDuration = NoOpObserverVec

	// BPFMapOps is the metric to measure the number of operations done to a
	// bpf map.
	BPFMapOps = NoOpCounterVec

	// TriggerPolicyUpdateTotal is the metric to count total number of
	// policy update triggers
	TriggerPolicyUpdateTotal = NoOpCounterVec

	// TriggerPolicyUpdateFolds is the current level folding that is
	// happening when running policy update triggers
	TriggerPolicyUpdateFolds = NoOpGauge

	// TriggerPolicyUpdateCallDuration measures the latency and call
	// duration of policy update triggers
	TriggerPolicyUpdateCallDuration = NoOpObserverVec

	// VersionMetric labelled by Cilium version
	VersionMetric = NoOpGaugeVec

	// APILimiterWaitHistoryDuration is a histogram that measures the
	// individual wait durations of API limiters
	APILimiterWaitHistoryDuration = NoOpObserverVec

	// APILimiterWaitDuration is the gauge of the current mean, min, and
	// max wait duration
	APILimiterWaitDuration = NoOpGaugeVec

	// APILimiterProcessingDuration is the gauge of the mean and estimated
	// processing duration
	APILimiterProcessingDuration = NoOpGaugeVec

	// APILimiterRequestsInFlight is the gauge of the current and max
	// requests in flight
	APILimiterRequestsInFlight = NoOpGaugeVec

	// APILimiterRateLimit is the gauge of the current rate limiting
	// configuration including limit and burst
	APILimiterRateLimit = NoOpGaugeVec

	// APILimiterAdjustmentFactor is the gauge representing the latest
	// adjustment factor that was applied
	APILimiterAdjustmentFactor = NoOpGaugeVec

	// APILimiterProcessedRequests is the counter of the number of
	// processed (successful and failed) requests
	APILimiterProcessedRequests = NoOpCounterVec
)

type Configuration struct {
	BootstrapTimesEnabled                   bool
	APIInteractionsEnabled                  bool
	NodeConnectivityStatusEnabled           bool
	NodeConnectivityLatencyEnabled          bool
	EndpointRegenerationCountEnabled        bool
	EndpointStateCountEnabled               bool
	EndpointRegenerationTimeStatsEnabled    bool
	EndpointPropagationDelayEnabled         bool
	PolicyCountEnabled                      bool
	PolicyRegenerationCountEnabled          bool
	PolicyRegenerationTimeStatsEnabled      bool
	PolicyRevisionEnabled                   bool
	PolicyImportErrorsEnabled               bool
	PolicyChangeTotalEnabled                bool
	PolicyEndpointStatusEnabled             bool
	PolicyImplementationDelayEnabled        bool
	CIDRGroupTranslationTimeStatsEnabled    bool
	CIDRGroupPoliciesCountEnabled           bool
	IdentityCountEnabled                    bool
	EventTSEnabled                          bool
	EventLagK8sEnabled                      bool
	EventTSContainerdEnabled                bool
	EventTSAPIEnabled                       bool
	ProxyRedirectsEnabled                   bool
	ProxyPolicyL7Enabled                    bool
	ProxyParseErrorsEnabled                 bool
	ProxyForwardedEnabled                   bool
	ProxyDeniedEnabled                      bool
	ProxyReceivedEnabled                    bool
	ProxyDatapathUpdateTimeoutEnabled       bool
	NoOpObserverVecEnabled                  bool
	DropCountEnabled                        bool
	DropBytesEnabled                        bool
	NoOpCounterVecEnabled                   bool
	ForwardBytesEnabled                     bool
	ConntrackGCRunsEnabled                  bool
	ConntrackGCKeyFallbacksEnabled          bool
	ConntrackGCSizeEnabled                  bool
	ConntrackGCDurationEnabled              bool
	ConntrackDumpResetsEnabled              bool
	SignalsHandledEnabled                   bool
	ServicesCountEnabled                    bool
	ErrorsWarningsEnabled                   bool
	ControllerRunsEnabled                   bool
	ControllerRunsDurationEnabled           bool
	SubprocessStartEnabled                  bool
	KubernetesEventProcessedEnabled         bool
	KubernetesEventReceivedEnabled          bool
	KubernetesTimeBetweenEventsEnabled      bool
	KubernetesAPIInteractionsEnabled        bool
	KubernetesAPICallsEnabled               bool
	KubernetesCNPStatusCompletionEnabled    bool
	KubernetesTerminatingEndpointsEnabled   bool
	IpamEventEnabled                        bool
	IPCacheErrorsTotalEnabled               bool
	IPCacheEventsTotalEnabled               bool
	KVStoreOperationsDurationEnabled        bool
	KVStoreEventsQueueDurationEnabled       bool
	KVStoreQuorumErrorsEnabled              bool
	FQDNGarbageCollectorCleanedTotalEnabled bool
	FQDNActiveNames                         bool
	FQDNActiveIPs                           bool
	FQDNActiveZombiesConnections            bool
	FQDNSemaphoreRejectedTotal              bool
	BPFSyscallDurationEnabled               bool
	BPFMapOps                               bool
	BPFMapPressure                          bool
	TriggerPolicyUpdateTotal                bool
	TriggerPolicyUpdateFolds                bool
	TriggerPolicyUpdateCallDuration         bool
	VersionMetric                           bool
	APILimiterWaitHistoryDuration           bool
	APILimiterWaitDuration                  bool
	APILimiterProcessingDuration            bool
	APILimiterRequestsInFlight              bool
	APILimiterRateLimit                     bool
	APILimiterAdjustmentFactor              bool
	APILimiterProcessedRequests             bool
}

func DefaultMetrics() map[string]struct{} {
	return map[string]struct{}{
		Namespace + "_" + SubsystemAgent + "_bootstrap_seconds":                      {},
		Namespace + "_" + SubsystemAgent + "_api_process_time_seconds":               {},
		Namespace + "_endpoint_regenerations_total":                                  {},
		Namespace + "_endpoint_state":                                                {},
		Namespace + "_endpoint_regeneration_time_stats_seconds":                      {},
		Namespace + "_policy":                                                        {},
		Namespace + "_policy_regeneration_total":                                     {},
		Namespace + "_policy_regeneration_time_stats_seconds":                        {},
		Namespace + "_policy_max_revision":                                           {},
		Namespace + "_policy_import_errors_total":                                    {},
		Namespace + "_policy_change_total":                                           {},
		Namespace + "_policy_endpoint_enforcement_status":                            {},
		Namespace + "_policy_implementation_delay":                                   {},
		Namespace + "_cidrgroup_policies":                                            {},
		Namespace + "_identity":                                                      {},
		Namespace + "_event_ts":                                                      {},
		Namespace + "_proxy_redirects":                                               {},
		Namespace + "_policy_l7_total":                                               {},
		Namespace + "_policy_l7_parse_errors_total":                                  {},
		Namespace + "_policy_l7_forwarded_total":                                     {},
		Namespace + "_policy_l7_denied_total":                                        {},
		Namespace + "_policy_l7_received_total":                                      {},
		Namespace + "_proxy_upstream_reply_seconds":                                  {},
		Namespace + "_drop_count_total":                                              {},
		Namespace + "_drop_bytes_total":                                              {},
		Namespace + "_forward_count_total":                                           {},
		Namespace + "_forward_bytes_total":                                           {},
		Namespace + "_endpoint_propagation_delay_seconds":                            {},
		Namespace + "_node_connectivity_status":                                      {},
		Namespace + "_node_connectivity_latency_seconds":                             {},
		Namespace + "_" + SubsystemDatapath + "_conntrack_dump_resets_total":         {},
		Namespace + "_" + SubsystemDatapath + "_conntrack_gc_runs_total":             {},
		Namespace + "_" + SubsystemDatapath + "_conntrack_gc_key_fallbacks_total":    {},
		Namespace + "_" + SubsystemDatapath + "_conntrack_gc_entries":                {},
		Namespace + "_" + SubsystemDatapath + "_conntrack_gc_duration_seconds":       {},
		Namespace + "_" + SubsystemDatapath + "_signals_handled_total":               {},
		Namespace + "_services_events_total":                                         {},
		Namespace + "_errors_warnings_total":                                         {},
		Namespace + "_controllers_runs_total":                                        {},
		Namespace + "_controllers_runs_duration_seconds":                             {},
		Namespace + "_subprocess_start_total":                                        {},
		Namespace + "_kubernetes_events_total":                                       {},
		Namespace + "_kubernetes_events_received_total":                              {},
		Namespace + "_" + SubsystemK8sClient + "_api_latency_time_seconds":           {},
		Namespace + "_" + SubsystemK8sClient + "_api_calls_total":                    {},
		Namespace + "_" + SubsystemK8s + "_cnp_status_completion_seconds":            {},
		Namespace + "_" + SubsystemK8s + "_terminating_endpoints_events_total":       {},
		Namespace + "_ipam_events_total":                                             {},
		Namespace + "_" + SubsystemKVStore + "_operations_duration_seconds":          {},
		Namespace + "_" + SubsystemKVStore + "_events_queue_seconds":                 {},
		Namespace + "_" + SubsystemKVStore + "_quorum_errors_total":                  {},
		Namespace + "_" + SubsystemIPCache + "_errors_total":                         {},
		Namespace + "_" + SubsystemFQDN + "_gc_deletions_total":                      {},
		Namespace + "_" + SubsystemBPF + "_map_ops_total":                            {},
		Namespace + "_" + SubsystemBPF + "_map_pressure":                             {},
		Namespace + "_" + SubsystemTriggers + "_policy_update_total":                 {},
		Namespace + "_" + SubsystemTriggers + "_policy_update_folds":                 {},
		Namespace + "_" + SubsystemTriggers + "_policy_update_call_duration_seconds": {},
		Namespace + "_version":                                                       {},
		Namespace + "_" + SubsystemAPILimiter + "_wait_duration_seconds":             {},
		Namespace + "_" + SubsystemAPILimiter + "_processing_duration_seconds":       {},
		Namespace + "_" + SubsystemAPILimiter + "_requests_in_flight":                {},
		Namespace + "_" + SubsystemAPILimiter + "_rate_limit":                        {},
		Namespace + "_" + SubsystemAPILimiter + "_adjustment_factor":                 {},
		Namespace + "_" + SubsystemAPILimiter + "_processed_requests_total":          {},
	}
}

// CreateConfiguration returns a Configuration with all metrics that are
// considered enabled from the given slice of metricsEnabled as well as a slice
// of prometheus.Collectors that must be registered in the prometheus default
// register.
func CreateConfiguration(metricsEnabled []string) (Configuration, []prometheus.Collector) {
	var collectors []prometheus.Collector
	c := Configuration{}

	for _, metricName := range metricsEnabled {
		switch metricName {
		default:
			logrus.WithField("metric", metricName).Warning("Metric does not exist, skipping")

		case Namespace + "_" + SubsystemAgent + "_bootstrap_seconds":
			BootstrapTimes = prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Namespace: Namespace,
				Subsystem: SubsystemAgent,
				Name:      "bootstrap_seconds",
				Help:      "Duration of bootstrap sequence",
			}, []string{LabelScope, LabelOutcome})

			collectors = append(collectors, BootstrapTimes)
			c.BootstrapTimesEnabled = true

		case Namespace + "_" + SubsystemAgent + "_api_process_time_seconds":
			APIInteractions = prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Namespace: Namespace,
				Subsystem: SubsystemAgent,
				Name:      "api_process_time_seconds",
				Help:      "Duration of processed API calls labeled by path, method and return code.",
			}, []string{LabelPath, LabelMethod, LabelAPIReturnCode})

			collectors = append(collectors, APIInteractions)
			c.APIInteractionsEnabled = true

		case Namespace + "_endpoint_regenerations_total":
			EndpointRegenerationTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "endpoint_regenerations_total",
				Help:      "Count of all endpoint regenerations that have completed, tagged by outcome",
			}, []string{"outcome"})

			collectors = append(collectors, EndpointRegenerationTotal)
			c.EndpointRegenerationCountEnabled = true

		case Namespace + "_endpoint_state":
			EndpointStateCount = prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Namespace: Namespace,
					Name:      "endpoint_state",
					Help:      "Count of all endpoints, tagged by different endpoint states",
				},
				[]string{"endpoint_state"},
			)

			collectors = append(collectors, EndpointStateCount)
			c.EndpointStateCountEnabled = true

		case Namespace + "_endpoint_regeneration_time_stats_seconds":
			EndpointRegenerationTimeStats = prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Namespace: Namespace,
				Name:      "endpoint_regeneration_time_stats_seconds",
				Help:      "Endpoint regeneration time stats labeled by the scope",
			}, []string{LabelScope, LabelStatus})

			collectors = append(collectors, EndpointRegenerationTimeStats)
			c.EndpointRegenerationTimeStatsEnabled = true

		case Namespace + "_policy":
			Policy = prometheus.NewGauge(prometheus.GaugeOpts{
				Namespace: Namespace,
				Name:      "policy",
				Help:      "Number of policies currently loaded",
			})

			collectors = append(collectors, Policy)
			c.PolicyCountEnabled = true

		case Namespace + "_policy_regeneration_total":
			PolicyRegenerationCount = prometheus.NewCounter(prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "policy_regeneration_total",
				Help:      "Total number of successful policy regenerations",
			})

			collectors = append(collectors, PolicyRegenerationCount)
			c.PolicyRegenerationCountEnabled = true

		case Namespace + "_policy_regeneration_time_stats_seconds":
			PolicyRegenerationTimeStats = prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Namespace: Namespace,
				Name:      "policy_regeneration_time_stats_seconds",
				Help:      "Policy regeneration time stats labeled by the scope",
			}, []string{LabelScope, LabelStatus})

			collectors = append(collectors, PolicyRegenerationTimeStats)
			c.PolicyRegenerationTimeStatsEnabled = true

		case Namespace + "_policy_max_revision":
			PolicyRevision = prometheus.NewGauge(prometheus.GaugeOpts{
				Namespace: Namespace,
				Name:      "policy_max_revision",
				Help:      "Highest policy revision number in the agent",
			})

			collectors = append(collectors, PolicyRevision)
			c.PolicyRegenerationTimeStatsEnabled = true

		case Namespace + "_policy_import_errors_total":
			PolicyImportErrorsTotal = prometheus.NewCounter(prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "policy_import_errors_total",
				Help:      "Number of times a policy import has failed",
			})

			collectors = append(collectors, PolicyImportErrorsTotal)
			c.PolicyImportErrorsEnabled = true

		case Namespace + "_policy_change_total":
			PolicyChangeTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "policy_change_total",
				Help:      "Number of policy changes by outcome",
			}, []string{"outcome"})

			collectors = append(collectors, PolicyChangeTotal)
			c.PolicyChangeTotalEnabled = true

		case Namespace + "_policy_endpoint_enforcement_status":
			PolicyEndpointStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Name:      "policy_endpoint_enforcement_status",
				Help:      "Number of endpoints labeled by policy enforcement status",
			}, []string{LabelPolicyEnforcement})

			collectors = append(collectors, PolicyEndpointStatus)
			c.PolicyEndpointStatusEnabled = true

		case Namespace + "_policy_implementation_delay":
			PolicyImplementationDelay = prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Namespace: Namespace,
				Name:      "policy_implementation_delay",
				Help:      "Time between a policy change and it being fully deployed into the datapath",
			}, []string{LabelPolicySource})

			collectors = append(collectors, PolicyImplementationDelay)
			c.PolicyImplementationDelayEnabled = true

		case Namespace + "_cidrgroup_translation_time_stats_seconds":
			CIDRGroupTranslationTimeStats = prometheus.NewHistogram(prometheus.HistogramOpts{
				Namespace: Namespace,
				Name:      "cidrgroup_translation_time_stats_seconds",
				Help:      "CIDRGroup translation time stats",
			})

			collectors = append(collectors, CIDRGroupTranslationTimeStats)
			c.CIDRGroupTranslationTimeStatsEnabled = true

		case Namespace + "_cidrgroup_policies":
			CIDRGroupPolicies = prometheus.NewGauge(prometheus.GaugeOpts{
				Namespace: Namespace,
				Name:      "cidrgroup_policies",
				Help:      "Number of CNPs and CCNPs referencing at least one CiliumCIDRGroup",
			})

			collectors = append(collectors, CIDRGroupPolicies)
			c.CIDRGroupPoliciesCountEnabled = true

		case Namespace + "_identity":
			Identity = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Name:      "identity",
				Help:      "Number of identities currently allocated",
			}, []string{LabelType})

			collectors = append(collectors, Identity)
			c.IdentityCountEnabled = true

		case Namespace + "_event_ts":
			EventTS = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Name:      "event_ts",
				Help:      "Last timestamp when we received an event",
			}, []string{LabelEventSource, LabelScope, LabelAction})

			collectors = append(collectors, EventTS)
			c.EventTSEnabled = true

			EventLagK8s = prometheus.NewGauge(prometheus.GaugeOpts{
				Namespace:   Namespace,
				Name:        "k8s_event_lag_seconds",
				Help:        "Lag for Kubernetes events - computed value between receiving a CNI ADD event from kubelet and a Pod event received from kube-api-server",
				ConstLabels: prometheus.Labels{"source": LabelEventSourceK8s},
			})

			collectors = append(collectors, EventLagK8s)
			c.EventLagK8sEnabled = true

		case Namespace + "_proxy_redirects":
			ProxyRedirects = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Name:      "proxy_redirects",
				Help:      "Number of redirects installed for endpoints, labeled by protocol",
			}, []string{LabelProtocolL7})

			collectors = append(collectors, ProxyRedirects)
			c.ProxyRedirectsEnabled = true

		case Namespace + "_policy_l7_total":
			ProxyPolicyL7Total = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "policy_l7_total",
				Help:      "Number of total proxy requests handled",
			}, []string{"rule"})

			collectors = append(collectors, ProxyPolicyL7Total)
			c.ProxyPolicyL7Enabled = true

		case Namespace + "_policy_l7_parse_errors_total":
			ProxyParseErrors = prometheus.NewCounter(prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "policy_l7_parse_errors_total",
				Help:      "Number of total L7 parse errors",
			})

			collectors = append(collectors, ProxyParseErrors)
			c.ProxyParseErrorsEnabled = true

		case Namespace + "_policy_l7_forwarded_total":
			ProxyForwarded = prometheus.NewCounter(prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "policy_l7_forwarded_total",
				Help:      "Number of total L7 forwarded requests/responses",
			})

			collectors = append(collectors, ProxyForwarded)
			c.ProxyForwardedEnabled = true

		case Namespace + "_policy_l7_denied_total":
			ProxyDenied = prometheus.NewCounter(prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "policy_l7_denied_total",
				Help:      "Number of total L7 denied requests/responses due to policy",
			})

			collectors = append(collectors, ProxyDenied)
			c.ProxyDeniedEnabled = true

		case Namespace + "_policy_l7_received_total":
			ProxyReceived = prometheus.NewCounter(prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "policy_l7_received_total",
				Help:      "Number of total L7 received requests/responses",
			})

			collectors = append(collectors, ProxyReceived)
			c.ProxyReceivedEnabled = true

		case Namespace + "_proxy_upstream_reply_seconds":
			ProxyUpstreamTime = prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Namespace: Namespace,
				Name:      "proxy_upstream_reply_seconds",
				Help:      "Seconds waited to get a reply from a upstream server",
			}, []string{"error", LabelProtocolL7, LabelScope})

			collectors = append(collectors, ProxyUpstreamTime)
			c.NoOpObserverVecEnabled = true

		case Namespace + "_proxy_datapath_update_timeout_total":
			ProxyDatapathUpdateTimeout = prometheus.NewCounter(prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "proxy_datapath_update_timeout_total",
				Help:      "Number of total datapath update timeouts due to FQDN IP updates",
			})

			collectors = append(collectors, ProxyDatapathUpdateTimeout)
			c.ProxyDatapathUpdateTimeoutEnabled = true

		case Namespace + "_drop_count_total":
			DropCount = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "drop_count_total",
				Help:      "Total dropped packets, tagged by drop reason and ingress/egress direction",
			},
				[]string{"reason", LabelDirection})

			collectors = append(collectors, DropCount)
			c.DropCountEnabled = true

		case Namespace + "_drop_bytes_total":
			DropBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "drop_bytes_total",
				Help:      "Total dropped bytes, tagged by drop reason and ingress/egress direction",
			},
				[]string{"reason", LabelDirection})

			collectors = append(collectors, DropBytes)
			c.DropBytesEnabled = true

		case Namespace + "_forward_count_total":
			ForwardCount = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "forward_count_total",
				Help:      "Total forwarded packets, tagged by ingress/egress direction",
			},
				[]string{LabelDirection})

			collectors = append(collectors, ForwardCount)
			c.NoOpCounterVecEnabled = true

		case Namespace + "_forward_bytes_total":
			ForwardBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "forward_bytes_total",
				Help:      "Total forwarded bytes, tagged by ingress/egress direction",
			},
				[]string{LabelDirection})

			collectors = append(collectors, ForwardBytes)
			c.ForwardBytesEnabled = true

		case Namespace + "_" + SubsystemDatapath + "_conntrack_gc_runs_total":
			ConntrackGCRuns = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Subsystem: SubsystemDatapath,
				Name:      "conntrack_gc_runs_total",
				Help: "Number of times that the conntrack garbage collector process was run " +
					"labeled by completion status",
			}, []string{LabelDatapathFamily, LabelProtocol, LabelStatus})

			collectors = append(collectors, ConntrackGCRuns)
			c.ConntrackGCRunsEnabled = true

		case Namespace + "_" + SubsystemDatapath + "_conntrack_gc_key_fallbacks_total":
			ConntrackGCKeyFallbacks = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Subsystem: SubsystemDatapath,
				Name:      "conntrack_gc_key_fallbacks_total",
				Help:      "Number of times a key fallback was needed when iterating over the BPF map",
			}, []string{LabelDatapathFamily, LabelProtocol})

			collectors = append(collectors, ConntrackGCKeyFallbacks)
			c.ConntrackGCKeyFallbacksEnabled = true

		case Namespace + "_" + SubsystemDatapath + "_conntrack_gc_entries":
			ConntrackGCSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: SubsystemDatapath,
				Name:      "conntrack_gc_entries",
				Help: "The number of alive and deleted conntrack entries at the end " +
					"of a garbage collector run labeled by datapath family.",
			}, []string{LabelDatapathFamily, LabelProtocol, LabelStatus})

			collectors = append(collectors, ConntrackGCSize)
			c.ConntrackGCSizeEnabled = true

			NatGCSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: SubsystemDatapath,
				Name:      "nat_gc_entries",
				Help: "The number of alive and deleted nat entries at the end " +
					"of a garbage collector run labeled by datapath family.",
			}, []string{LabelDatapathFamily, LabelDirection, LabelStatus})

			collectors = append(collectors, NatGCSize)

		case Namespace + "_" + SubsystemDatapath + "_conntrack_gc_duration_seconds":
			ConntrackGCDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Namespace: Namespace,
				Subsystem: SubsystemDatapath,
				Name:      "conntrack_gc_duration_seconds",
				Help: "Duration in seconds of the garbage collector process " +
					"labeled by datapath family and completion status",
			}, []string{LabelDatapathFamily, LabelProtocol, LabelStatus})

			collectors = append(collectors, ConntrackGCDuration)
			c.ConntrackGCDurationEnabled = true

		case Namespace + "_" + SubsystemDatapath + "_conntrack_dump_resets_total":
			ConntrackDumpResets = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Subsystem: SubsystemDatapath,
				Name:      "conntrack_dump_resets_total",
				Help:      "Number of conntrack dump resets. Happens when a BPF entry gets removed while dumping the map is in progress",
			}, []string{LabelDatapathArea, LabelDatapathName, LabelDatapathFamily})

			collectors = append(collectors, ConntrackDumpResets)
			c.ConntrackDumpResetsEnabled = true

		case Namespace + "_" + SubsystemDatapath + "_signals_handled_total":
			SignalsHandled = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Subsystem: SubsystemDatapath,
				Name:      "signals_handled_total",
				Help: "Number of times that the datapath signal handler process was run " +
					"labeled by signal type, data and completion status",
			}, []string{LabelSignalType, LabelSignalData, LabelStatus})

			collectors = append(collectors, SignalsHandled)
			c.SignalsHandledEnabled = true

		case Namespace + "_services_events_total":
			ServicesCount = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "services_events_total",
				Help:      "Number of services events labeled by action type",
			}, []string{LabelAction})

			collectors = append(collectors, ServicesCount)
			c.ServicesCountEnabled = true

		case Namespace + "_errors_warnings_total":
			ErrorsWarnings = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "errors_warnings_total",
				Help:      "Number of total errors in cilium-agent instances",
			}, []string{"level", "subsystem"})

			collectors = append(collectors, ErrorsWarnings)
			c.ErrorsWarningsEnabled = true

		case Namespace + "_controllers_runs_total":
			ControllerRuns = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "controllers_runs_total",
				Help:      "Number of times that a controller process was run labeled by completion status",
			}, []string{LabelStatus})

			collectors = append(collectors, ControllerRuns)
			c.ControllerRunsEnabled = true

		case Namespace + "_controllers_runs_duration_seconds":
			ControllerRunsDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Namespace: Namespace,
				Name:      "controllers_runs_duration_seconds",
				Help:      "Duration in seconds of the controller process labeled by completion status",
			}, []string{LabelStatus})

			collectors = append(collectors, ControllerRunsDuration)
			c.ControllerRunsDurationEnabled = true

		case Namespace + "_subprocess_start_total":
			SubprocessStart = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "subprocess_start_total",
				Help:      "Number of times that Cilium has started a subprocess, labeled by subsystem",
			}, []string{LabelSubsystem})

			collectors = append(collectors, SubprocessStart)
			c.SubprocessStartEnabled = true

		case Namespace + "_kubernetes_events_total":
			KubernetesEventProcessed = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "kubernetes_events_total",
				Help:      "Number of Kubernetes events processed labeled by scope, action and execution result",
			}, []string{LabelScope, LabelAction, LabelStatus})

			collectors = append(collectors, KubernetesEventProcessed)
			c.KubernetesEventProcessedEnabled = true

		case Namespace + "_kubernetes_events_received_total":
			KubernetesEventReceived = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "kubernetes_events_received_total",
				Help:      "Number of Kubernetes events received labeled by scope, action, valid data and equalness",
			}, []string{LabelScope, LabelAction, "valid", "equal"})

			collectors = append(collectors, KubernetesEventReceived)
			c.KubernetesEventReceivedEnabled = true

		case Namespace + "_" + SubsystemK8sClient + "_api_latency_time_seconds":
			KubernetesAPIInteractions = prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Namespace: Namespace,
				Subsystem: SubsystemK8sClient,
				Name:      "api_latency_time_seconds",
				Help:      "Duration of processed API calls labeled by path and method.",
			}, []string{LabelPath, LabelMethod})

			collectors = append(collectors, KubernetesAPIInteractions)
			c.KubernetesAPIInteractionsEnabled = true

		case Namespace + "_" + SubsystemK8sClient + "_api_calls_total":
			KubernetesAPICallsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Subsystem: SubsystemK8sClient,
				Name:      "api_calls_total",
				Help:      "Number of API calls made to kube-apiserver labeled by host, method and return code.",
			}, []string{"host", LabelMethod, LabelAPIReturnCode})

			collectors = append(collectors, KubernetesAPICallsTotal)
			c.KubernetesAPICallsEnabled = true

		case Namespace + "_" + SubsystemK8s + "_cnp_status_completion_seconds":
			KubernetesCNPStatusCompletion = prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Namespace: Namespace,
				Subsystem: SubsystemK8s,
				Name:      "cnp_status_completion_seconds",
				Help:      "Duration in seconds in how long it took to complete a CNP status update",
			}, []string{LabelAttempts, LabelOutcome})

			collectors = append(collectors, KubernetesCNPStatusCompletion)
			c.KubernetesCNPStatusCompletionEnabled = true

		case Namespace + "_" + SubsystemK8s + "_terminating_endpoints_events_total":
			TerminatingEndpointsEvents = prometheus.NewCounter(prometheus.CounterOpts{
				Namespace: Namespace,
				Subsystem: SubsystemK8s,
				Name:      "terminating_endpoints_events_total",
				Help:      "Number of terminating endpoint events received from Kubernetes",
			})

			collectors = append(collectors, TerminatingEndpointsEvents)
			c.KubernetesTerminatingEndpointsEnabled = true

		case Namespace + "_ipam_events_total":
			IpamEvent = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "ipam_events_total",
				Help:      "Number of IPAM events received labeled by action and datapath family type",
			}, []string{LabelAction, LabelDatapathFamily})

			collectors = append(collectors, IpamEvent)
			c.IpamEventEnabled = true

		case Namespace + "_" + SubsystemKVStore + "_operations_duration_seconds":
			KVStoreOperationsDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Namespace: Namespace,
				Subsystem: SubsystemKVStore,
				Name:      "operations_duration_seconds",
				Help:      "Duration in seconds of kvstore operations",
			}, []string{LabelScope, LabelKind, LabelAction, LabelOutcome})

			collectors = append(collectors, KVStoreOperationsDuration)
			c.KVStoreOperationsDurationEnabled = true

		case Namespace + "_" + SubsystemKVStore + "_events_queue_seconds":
			KVStoreEventsQueueDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Namespace: Namespace,
				Subsystem: SubsystemKVStore,
				Name:      "events_queue_seconds",
				Help:      "Duration in seconds of time received event was blocked before it could be queued",
				Buckets:   []float64{.002, .005, .01, .015, .025, .05, .1, .25, .5, .75, 1},
			}, []string{LabelScope, LabelAction})

			collectors = append(collectors, KVStoreEventsQueueDuration)
			c.KVStoreEventsQueueDurationEnabled = true

		case Namespace + "_" + SubsystemKVStore + "_quorum_errors_total":
			KVStoreQuorumErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Subsystem: SubsystemKVStore,
				Name:      "quorum_errors_total",
				Help:      "Number of quorum errors",
			}, []string{LabelError})

			collectors = append(collectors, KVStoreQuorumErrors)
			c.KVStoreQuorumErrorsEnabled = true

		case Namespace + "_" + SubsystemIPCache + "_errors_total":
			IPCacheErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Subsystem: SubsystemIPCache,
				Name:      "errors_total",
				Help:      "Number of errors interacting with the IP to Identity cache",
			}, []string{LabelType, LabelError})

			collectors = append(collectors, IPCacheErrorsTotal)
			c.IPCacheErrorsTotalEnabled = true

		case Namespace + "_" + SubsystemIPCache + "_events_total":
			IPCacheEventsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Subsystem: SubsystemIPCache,
				Name:      "events_total",
				Help:      "Number of events interacting with the IP to Identity cache",
			}, []string{LabelType})

			collectors = append(collectors, IPCacheEventsTotal)
			c.IPCacheEventsTotalEnabled = true

		case Namespace + "_" + SubsystemFQDN + "_gc_deletions_total":
			FQDNGarbageCollectorCleanedTotal = prometheus.NewCounter(prometheus.CounterOpts{
				Namespace: Namespace,
				Subsystem: SubsystemFQDN,
				Name:      "gc_deletions_total",
				Help:      "Number of FQDNs that have been cleaned on FQDN Garbage collector job",
			})

			collectors = append(collectors, FQDNGarbageCollectorCleanedTotal)
			c.FQDNGarbageCollectorCleanedTotalEnabled = true

		case Namespace + "_" + SubsystemFQDN + "_active_names":
			FQDNActiveNames = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: SubsystemFQDN,
				Name:      "active_names",
				Help:      "Number of domains inside the DNS cache that have not expired (by TTL), per endpoint",
			}, []string{LabelPeerEndpoint})

			collectors = append(collectors, FQDNActiveNames)
			c.FQDNActiveNames = true

		case Namespace + "_" + SubsystemFQDN + "_active_ips":
			FQDNActiveIPs = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: SubsystemFQDN,
				Name:      "active_ips",
				Help:      "Number of IPs inside the DNS cache associated with a domain that has not expired (by TTL), per endpoint",
			}, []string{LabelPeerEndpoint})

			collectors = append(collectors, FQDNActiveIPs)
			c.FQDNActiveIPs = true

		case Namespace + "_" + SubsystemFQDN + "_alive_zombie_connections":
			FQDNAliveZombieConnections = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: SubsystemFQDN,
				Name:      "alive_zombie_connections",
				Help:      "Number of IPs associated with domains that have expired (by TTL) yet still associated with an active connection (aka zombie), per endpoint",
			}, []string{LabelPeerEndpoint})

			collectors = append(collectors, FQDNAliveZombieConnections)
			c.FQDNActiveZombiesConnections = true

		case Namespace + "_" + SubsystemFQDN + "_semaphore_rejected_total":
			FQDNSemaphoreRejectedTotal = prometheus.NewCounter(prometheus.CounterOpts{
				Namespace: Namespace,
				Subsystem: SubsystemFQDN,
				Name:      "semaphore_rejected_total",
				Help:      "Number of DNS request rejected by the DNS Proxy's admission semaphore",
			})

			collectors = append(collectors, FQDNSemaphoreRejectedTotal)
			c.FQDNSemaphoreRejectedTotal = true

		case Namespace + "_" + SubsystemBPF + "_syscall_duration_seconds":
			BPFSyscallDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Namespace: Namespace,
				Subsystem: SubsystemBPF,
				Name:      "syscall_duration_seconds",
				Help:      "Duration of BPF system calls",
			}, []string{LabelOperation, LabelOutcome})

			collectors = append(collectors, BPFSyscallDuration)
			c.BPFSyscallDurationEnabled = true

		case Namespace + "_" + SubsystemBPF + "_map_ops_total":
			BPFMapOps = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Subsystem: SubsystemBPF,
				Name:      "map_ops_total",
				Help:      "Total operations on map, tagged by map name",
			}, []string{LabelMapName, LabelOperation, LabelOutcome})

			collectors = append(collectors, BPFMapOps)
			c.BPFMapOps = true

		case Namespace + "_" + SubsystemBPF + "_map_pressure":
			c.BPFMapPressure = true

		case Namespace + "_" + SubsystemTriggers + "_policy_update_total":
			TriggerPolicyUpdateTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Subsystem: SubsystemTriggers,
				Name:      "policy_update_total",
				Help:      "Total number of policy update trigger invocations labeled by reason",
			}, []string{"reason"})

			collectors = append(collectors, TriggerPolicyUpdateTotal)
			c.TriggerPolicyUpdateTotal = true

		case Namespace + "_" + SubsystemTriggers + "_policy_update_folds":
			TriggerPolicyUpdateFolds = prometheus.NewGauge(prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: SubsystemTriggers,
				Name:      "policy_update_folds",
				Help:      "Current number of folds",
			})

			collectors = append(collectors, TriggerPolicyUpdateFolds)
			c.TriggerPolicyUpdateFolds = true

		case Namespace + "_" + SubsystemTriggers + "_policy_update_call_duration_seconds":
			TriggerPolicyUpdateCallDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Namespace: Namespace,
				Subsystem: SubsystemTriggers,
				Name:      "policy_update_call_duration_seconds",
				Help:      "Duration of policy update trigger",
			}, []string{LabelType})

			collectors = append(collectors, TriggerPolicyUpdateCallDuration)
			c.TriggerPolicyUpdateCallDuration = true

		case Namespace + "_version":
			VersionMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Name:      "version",
				Help:      "Cilium version",
			}, []string{LabelVersion, LabelVersionRevision, LabelArch})

			v := version.GetCiliumVersion()
			VersionMetric.WithLabelValues(v.Version, v.Revision, v.Arch)

			collectors = append(collectors, VersionMetric)
			c.VersionMetric = true

		case Namespace + "_" + SubsystemAPILimiter + "_wait_history_duration_seconds":
			APILimiterWaitHistoryDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Namespace: Namespace,
				Subsystem: SubsystemAPILimiter,
				Name:      "wait_history_duration_seconds",
				Help:      "Histogram over duration of waiting period for API calls subjects to rate limiting",
			}, []string{"api_call"})

			collectors = append(collectors, APILimiterWaitHistoryDuration)
			c.APILimiterWaitHistoryDuration = true

		case Namespace + "_" + SubsystemAPILimiter + "_wait_duration_seconds":
			APILimiterWaitDuration = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: SubsystemAPILimiter,
				Name:      "wait_duration_seconds",
				Help:      "Current wait time for api calls",
			}, []string{"api_call", "value"})

			collectors = append(collectors, APILimiterWaitDuration)
			c.APILimiterWaitDuration = true

		case Namespace + "_" + SubsystemAPILimiter + "_processing_duration_seconds":
			APILimiterProcessingDuration = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: SubsystemAPILimiter,
				Name:      "processing_duration_seconds",
				Help:      "Current processing time of api call",
			}, []string{"api_call", "value"})

			collectors = append(collectors, APILimiterProcessingDuration)
			c.APILimiterProcessingDuration = true

		case Namespace + "_" + SubsystemAPILimiter + "_requests_in_flight":
			APILimiterRequestsInFlight = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: SubsystemAPILimiter,
				Name:      "requests_in_flight",
				Help:      "Current requests in flight",
			}, []string{"api_call", "value"})

			collectors = append(collectors, APILimiterRequestsInFlight)
			c.APILimiterRequestsInFlight = true

		case Namespace + "_" + SubsystemAPILimiter + "_rate_limit":
			APILimiterRateLimit = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: SubsystemAPILimiter,
				Name:      "rate_limit",
				Help:      "Current rate limiting configuration",
			}, []string{"api_call", "value"})

			collectors = append(collectors, APILimiterRateLimit)
			c.APILimiterRateLimit = true

		case Namespace + "_" + SubsystemAPILimiter + "_adjustment_factor":
			APILimiterAdjustmentFactor = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: SubsystemAPILimiter,
				Name:      "adjustment_factor",
				Help:      "Current adjustment factor while auto adjusting",
			}, []string{"api_call"})

			collectors = append(collectors, APILimiterAdjustmentFactor)
			c.APILimiterAdjustmentFactor = true

		case Namespace + "_" + SubsystemAPILimiter + "_processed_requests_total":
			APILimiterProcessedRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: Namespace,
				Subsystem: SubsystemAPILimiter,
				Name:      "processed_requests_total",
				Help:      "Total number of API requests processed",
			}, []string{"api_call", LabelOutcome})

			collectors = append(collectors, APILimiterProcessedRequests)
			c.APILimiterProcessedRequests = true

		case Namespace + "_endpoint_propagation_delay_seconds":
			EndpointPropagationDelay = prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Namespace: Namespace,
				Name:      "endpoint_propagation_delay_seconds",
				Help:      "CiliumEndpoint roundtrip propagation delay in seconds",
				Buckets:   []float64{.05, .1, 1, 5, 30, 60, 120, 240, 300, 600},
			}, []string{})

			collectors = append(collectors, EndpointPropagationDelay)
			c.EndpointPropagationDelayEnabled = true

		case Namespace + "_node_connectivity_status":
			NodeConnectivityStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Name:      "node_connectivity_status",
				Help:      "The last observed status of both ICMP and HTTP connectivity between the current Cilium agent and other Cilium nodes",
			}, []string{
				LabelSourceCluster,
				LabelSourceNodeName,
				LabelTargetCluster,
				LabelTargetNodeName,
				LabelTargetNodeType,
				LabelType,
			})

			collectors = append(collectors, NodeConnectivityStatus)
			c.NodeConnectivityStatusEnabled = true

		case Namespace + "_node_connectivity_latency_seconds":
			NodeConnectivityLatency = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Name:      "node_connectivity_latency_seconds",
				Help:      "The last observed latency between the current Cilium agent and other Cilium nodes in seconds",
			}, []string{
				LabelSourceCluster,
				LabelSourceNodeName,
				LabelTargetCluster,
				LabelTargetNodeName,
				LabelTargetNodeIP,
				LabelTargetNodeType,
				LabelType,
				LabelProtocol,
				LabelAddressType,
			})

			collectors = append(collectors, NodeConnectivityLatency)
			c.NodeConnectivityLatencyEnabled = true
		}

	}

	return c, collectors
}

// GaugeWithThreshold is a prometheus gauge that registers itself with
// prometheus if over a threshold value and unregisters when under.
type GaugeWithThreshold struct {
	gauge     prometheus.Gauge
	threshold float64
	active    bool
}

// Set the value of the GaugeWithThreshold.
func (gwt *GaugeWithThreshold) Set(value float64) {
	overThreshold := value > gwt.threshold
	if gwt.active && !overThreshold {
		gwt.active = !Unregister(gwt.gauge)
		if gwt.active {
			logrus.WithField("metric", gwt.gauge.Desc().String()).Warning("Failed to unregister metric")
		}
	} else if !gwt.active && overThreshold {
		err := Register(gwt.gauge)
		gwt.active = err == nil
		if err != nil {
			logrus.WithField("metric", gwt.gauge.Desc().String()).WithError(err).Warning("Failed to register metric")
		}
	}

	gwt.gauge.Set(value)
}

// NewGaugeWithThreshold creates a new GaugeWithThreshold.
func NewGaugeWithThreshold(name string, subsystem string, desc string, labels map[string]string, threshold float64) *GaugeWithThreshold {
	return &GaugeWithThreshold{
		gauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   Namespace,
			Subsystem:   subsystem,
			Name:        name,
			Help:        desc,
			ConstLabels: labels,
		}),
		threshold: threshold,
		active:    false,
	}
}

// NewBPFMapPressureGauge creates a new GaugeWithThreshold for the
// cilium_bpf_map_pressure metric with the map name as constant label.
func NewBPFMapPressureGauge(mapname string, threshold float64) *GaugeWithThreshold {
	return NewGaugeWithThreshold(
		"map_pressure",
		SubsystemBPF,
		"Fill percentage of map, tagged by map name",
		map[string]string{
			LabelMapName: mapname,
		},
		threshold,
	)
}

func init() {
	ResetMetrics()
}

func registerDefaultMetrics() {
	MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{Namespace: Namespace}))
	MustRegister(collectors.NewGoCollector(
		collectors.WithGoCollectorRuntimeMetrics(
			collectors.GoRuntimeMetricsRule{Matcher: goCustomCollectorsRX},
		)))
	MustRegister(newStatusCollector())
	MustRegister(newbpfCollector())
}

func ResetMetrics() {
	registry = prometheus.NewPedanticRegistry()
	registerDefaultMetrics()
}

// MustRegister adds the collector to the registry, exposing this metric to
// prometheus scrapes.
// It will panic on error.
func MustRegister(c ...prometheus.Collector) {
	registry.MustRegister(c...)
}

// Register registers a collector
func Register(c prometheus.Collector) error {
	return registry.Register(c)
}

// RegisterList registers a list of collectors. If registration of one
// collector fails, no collector is registered.
func RegisterList(list []prometheus.Collector) error {
	registered := []prometheus.Collector{}

	for _, c := range list {
		if err := Register(c); err != nil {
			for _, c := range registered {
				Unregister(c)
			}
			return err
		}

		registered = append(registered, c)
	}

	return nil
}

// Unregister unregisters a collector
func Unregister(c prometheus.Collector) bool {
	return registry.Unregister(c)
}

// Enable begins serving prometheus metrics on the address passed in. Addresses
// of the form ":8080" will bind the port on all interfaces.
func Enable(addr string) <-chan error {
	errs := make(chan error, 1)

	go func() {
		// The Handler function provides a default handler to expose metrics
		// via an HTTP server. "/metrics" is the usual endpoint for that.
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
		srv := http.Server{
			Addr:    addr,
			Handler: mux,
		}
		errs <- srv.ListenAndServe()
	}()

	return errs
}

// GetCounterValue returns the current value
// stored for the counter
func GetCounterValue(m prometheus.Counter) float64 {
	var pm dto.Metric
	err := m.Write(&pm)
	if err == nil {
		return *pm.Counter.Value
	}
	return 0
}

// GetGaugeValue returns the current value stored for the gauge. This function
// is useful in tests.
func GetGaugeValue(m prometheus.Gauge) float64 {
	var pm dto.Metric
	err := m.Write(&pm)
	if err == nil {
		return *pm.Gauge.Value
	}
	return 0
}

// DumpMetrics gets the current Cilium metrics and dumps all into a
// models.Metrics structure.If metrics cannot be retrieved, returns an error
func DumpMetrics() ([]*models.Metric, error) {
	result := []*models.Metric{}
	currentMetrics, err := registry.Gather()
	if err != nil {
		return result, err
	}

	for _, val := range currentMetrics {

		metricName := val.GetName()
		metricType := val.GetType()

		for _, metricLabel := range val.Metric {
			labels := map[string]string{}
			for _, label := range metricLabel.GetLabel() {
				labels[label.GetName()] = label.GetValue()
			}

			var value float64
			switch metricType {
			case dto.MetricType_COUNTER:
				value = metricLabel.Counter.GetValue()
			case dto.MetricType_GAUGE:
				value = metricLabel.GetGauge().GetValue()
			case dto.MetricType_UNTYPED:
				value = metricLabel.GetUntyped().GetValue()
			case dto.MetricType_SUMMARY:
				value = metricLabel.GetSummary().GetSampleSum()
			case dto.MetricType_HISTOGRAM:
				value = metricLabel.GetHistogram().GetSampleSum()
			default:
				continue
			}

			metric := &models.Metric{
				Name:   metricName,
				Labels: labels,
				Value:  value,
			}
			result = append(result, metric)
		}
	}
	return result, nil
}

// Error2Outcome converts an error to LabelOutcome
func Error2Outcome(err error) string {
	if err != nil {
		return LabelValueOutcomeFail
	}

	return LabelValueOutcomeSuccess
}

func BoolToFloat64(v bool) float64 {
	if v {
		return 1
	}
	return 0
}
