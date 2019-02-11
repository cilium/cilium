// Copyright 2017-2018 Authors of Cilium
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

// Package metrics holds prometheus metrics objects and related utility functions. It
// does not abstract away the prometheus client but the caller rarely needs to
// refer to prometheus directly.
package metrics

// Adding a metric
// - Add a metric object of the appropriate type as an exported variable
// - Register the new object in the init function

import (
	"github.com/cilium/cilium/api/v1/models"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
)

const (
	// BuildStateWaiting is the value of LabelBuildState to describe
	// the number of entries waiting in the build queue
	BuildStateWaiting = "waiting"

	// BuildStateBlocked is the value of LabelBuildState to describe
	// the number of entries scheduled for building but blocked due to
	// build conditions
	BuildStateBlocked = "blocked"

	// BuildStateRunning is the value of LabelBuildState to describe
	// the number of builds currently running
	BuildStateRunning = "running"

	// ErrorTimeout is the value used to notify timeout errors.
	ErrorTimeout = "timeout"

	// ErrorProxy is the value used to notify errors on Proxy.
	ErrorProxy = "proxy"

	//L7DNS is the value used to report DNS label on metrics
	L7DNS = "dns"
)

var (
	registry = prometheus.NewPedanticRegistry()

	// Namespace is used to scope metrics from cilium. It is prepended to metric
	// names and separated with a '_'
	Namespace = "cilium"

	// Datapath is the subsystem to scope metrics related to management of
	// the datapath. It is prepended to metric names and separated with a '_'.
	Datapath = "datapath"

	// Labels

	// LabelValueOutcomeSuccess is used as a successful outcome of an operation
	LabelValueOutcomeSuccess = "success"

	// LabelValueOutcomeFail is used as an unsuccessful outcome of an operation
	LabelValueOutcomeFail = "fail"

	// LabelEventSourceAPI marks event-related metrics that come from the API
	LabelEventSourceAPI = "api"

	// LabelEventSourceK8s marks event-related metrics that come from k8s
	LabelEventSourceK8s = "k8s"

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

	// LabelStatus the label from completed task
	LabelStatus = "status"

	//LabelPolicyEnforcement is the label used to see the enforcement status
	LabelPolicyEnforcement = "enforcement"

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

	// LabelKind is the kind a label
	LabelKind = "kind"

	// Endpoint

	// EndpointCount is a function used to collect this metric.
	// It must be thread-safe.
	EndpointCount prometheus.GaugeFunc

	// EndpointCountRegenerating is the number of endpoints currently regenerating
	EndpointCountRegenerating = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "endpoint_regenerating",
		Help:      "Number of endpoints currently regenerating. Deprecated. Use endpoint_state with proper labels instead",
	})

	// EndpointRegenerationCount is a count of the number of times any endpoint
	// has been regenerated and success/fail outcome
	EndpointRegenerationCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "endpoint_regenerations",
		Help:      "Count of all endpoint regenerations that have completed, tagged by outcome",
	},
		[]string{"outcome"})

	// Deprecated: this metric will be removed in Cilium 1.4
	// EndpointRegenerationTime is the total time taken to regenerate endpoint
	EndpointRegenerationTime = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "endpoint_regeneration_seconds_total",
		Help:      "Total sum of successful endpoint regeneration times (Deprecated)",
	})

	// Deprecated: this metric will be removed in Cilium 1.4
	// EndpointRegenerationTimeSquare is the sum of squares of total time taken
	// to regenerate endpoint.
	EndpointRegenerationTimeSquare = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "endpoint_regeneration_square_seconds_total",
		Help:      "Total sum of squares of successful endpoint regeneration times (Deprecated)",
	})

	// EndpointStateCount is the total count of the endpoints in various states.
	EndpointStateCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "endpoint_state",
			Help:      "Count of all endpoints, tagged by different endpoint states",
		},
		[]string{"endpoint_state"},
	)

	// EndpointRegenerationTimeStats is the total time taken to regenerate
	// endpoints, labeled by span name and status ("success" or "failure")
	EndpointRegenerationTimeStats = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: Namespace,
		Name:      "endpoint_regeneration_time_stats_seconds",
		Help:      "Endpoint regeneration time stats labeled by the scope",
	}, []string{LabelScope, LabelStatus})

	// Policy

	// PolicyCount is the number of policies loaded into the agent
	PolicyCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "policy_count",
		Help:      "Number of policies currently loaded",
	})

	// PolicyRegenerationCount is the total number of successful policy
	// regenerations.
	PolicyRegenerationCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "policy_regeneration_total",
		Help:      "Total number of successful policy regenerations",
	})

	// PolicyRegenerationTime is the total time taken to generate policies
	PolicyRegenerationTime = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "policy_regeneration_seconds_total",
		Help:      "Total sum of successful policy regeneration times",
	})

	// PolicyRegenerationTimeSquare is the sum of squares of total time taken
	// to generate policies
	PolicyRegenerationTimeSquare = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "policy_regeneration_square_seconds_total",
		Help:      "Total sum of squares of successful policy regeneration times",
	})

	// PolicyRevision is the current policy revision number for this agent
	PolicyRevision = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "policy_max_revision",
		Help:      "Highest policy revision number in the agent",
	})

	// PolicyImportErrors is a count of failed policy imports
	PolicyImportErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "policy_import_errors",
		Help:      "Number of times a policy import has failed",
	})

	// PolicyEndpointStatus is the number of endpoints with policy labeled by enforcement type
	PolicyEndpointStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "policy_endpoint_enforcement_status",
		Help:      "Number of endpoints labeled by policy enforcement status",
	}, []string{LabelPolicyEnforcement})

	// Events

	// EventTS*is the time in seconds since epoch that we last received an
	// event that we will handle
	// source is one of k8s, docker or apia

	// EventTSK8s is the timestamp of k8s events
	EventTSK8s = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace:   Namespace,
		Name:        "event_ts",
		Help:        "Last timestamp when we received an event",
		ConstLabels: prometheus.Labels{"source": LabelEventSourceK8s},
	})

	// EventTSContainerd is the timestamp of docker events
	EventTSContainerd = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace:   Namespace,
		Name:        "event_ts",
		Help:        "Last timestamp when we received an event",
		ConstLabels: prometheus.Labels{"source": LabelEventSourceContainerd},
	})

	// EventTSAPI is the timestamp of docker events
	EventTSAPI = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace:   Namespace,
		Name:        "event_ts",
		Help:        "Last timestamp when we received an event",
		ConstLabels: prometheus.Labels{"source": LabelEventSourceAPI},
	})

	// L7 statistics

	// ProxyRedirects is the number of redirects labelled by protocol
	ProxyRedirects = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "proxy_redirects",
		Help:      "Number of redirects installed for endpoints, labeled by protocol",
	}, []string{LabelProtocolL7})

	// ProxyParseErrors is a count of failed parse errors on proxy
	ProxyParseErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "policy_l7_parse_errors_total",
		Help:      "Number of total L7 parse errors",
	})

	// ProxyForwarded is a count of all forwarded requests by proxy
	ProxyForwarded = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "policy_l7_forwarded_total",
		Help:      "Number of total L7 forwarded requests/responses",
	})

	// ProxyDenied is a count of all denied requests by policy by the proxy
	ProxyDenied = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "policy_l7_denied_total",
		Help:      "Number of total L7 denied requests/responses due to policy",
	})

	// ProxyReceived is a count of all received requests by the proxy
	ProxyReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "policy_l7_received_total",
		Help:      "Number of total L7 received requests/responses",
	})

	// ProxyUpstreamTime is how long the upstream server took to reply labeled
	// by error, protocol and span time
	ProxyUpstreamTime = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: Namespace,
		Name:      "proxy_upstream_reply_seconds",
		Help:      "Seconds waited to get a reply from a upstream server",
	}, []string{"error", LabelProtocolL7, LabelScope})

	// L3-L4 statistics

	// DropCount is the total drop requests,
	// tagged by drop reason and direction(ingress/egress)
	DropCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "drop_count_total",
		Help:      "Total dropped packets, tagged by drop reason and ingress/egress direction",
	},
		[]string{"reason", "direction"})

	// DropBytes is the total dropped bytes,
	// tagged by drop reason and direction(ingress/egress)
	DropBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "drop_bytes_total",
		Help:      "Total dropped bytes, tagged by drop reason and ingress/egress direction",
	},
		[]string{"reason", "direction"})

	// ForwardCount is the total forwarded packets,
	// tagged by ingress/egress direction
	ForwardCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "forward_count_total",
		Help:      "Total forwarded packets, tagged by ingress/egress direction",
	},
		[]string{"direction"})

	// ForwardBytes is the total forwarded bytes,
	// tagged by ingress/egress direction
	ForwardBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "forward_bytes_total",
		Help:      "Total forwarded bytes, tagged by ingress/egress direction",
	},
		[]string{"direction"})

	// Datapath statistics

	// DatapathErrors is the number of errors managing datapath components
	// such as BPF maps.
	DatapathErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: Datapath,
		Name:      "errors_total",
		Help:      "Number of errors that occurred in the datapath or datapath management",
	}, []string{LabelDatapathArea, LabelDatapathName, LabelDatapathFamily})

	// ConntrackGCRuns is the number of times that the conntrack GC
	// process was run.
	ConntrackGCRuns = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: Datapath,
		Name:      "conntrack_gc_runs_total",
		Help: "Number of times that the conntrack garbage collector process was run " +
			"labeled by completion status",
	}, []string{LabelDatapathFamily, LabelProtocol, LabelStatus})

	// ConntrackGCKeyFallbacks number of times that the conntrack key fallback was invalid.
	ConntrackGCKeyFallbacks = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: Datapath,
		Name:      "conntrack_gc_key_fallbacks_total",
		Help:      "Number of times a key fallback was needed when iterating over the BPF map",
	}, []string{LabelDatapathFamily, LabelProtocol})

	// ConntrackGCSize the number of entries in the conntrack table
	ConntrackGCSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: Datapath,
		Name:      "conntrack_gc_entries",
		Help: "The number of alive and deleted conntrack entries at the end " +
			"of a garbage collector run labeled by datapath family.",
	}, []string{LabelDatapathFamily, LabelProtocol, LabelStatus})

	// ConntrackGCDuration the duration of the conntrack GC process in milliseconds.
	ConntrackGCDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: Namespace,
		Subsystem: Datapath,
		Name:      "conntrack_gc_duration_seconds",
		Help: "Duration in seconds of the garbage collector process " +
			"labeled by datapath family and completion status",
	}, []string{LabelDatapathFamily, LabelProtocol, LabelStatus})

	// Services

	// ServicesCount number of services
	ServicesCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "services_events_total",
		Help:      "Number of services events labeled by action type",
	}, []string{LabelAction})

	// Errors and warnings

	// ErrorsWarnings is the number of errors and warnings in cilium-agent instances
	ErrorsWarnings = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "errors_warnings_total",
		Help:      "Number of total errors in cilium-agent instances",
	}, []string{"level", "subsystem"})

	// ControllerRuns is the number of times that a controller process runs.
	ControllerRuns = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "controllers_runs_total",
		Help:      "Number of times that a controller process was run labeled by completion status",
	}, []string{LabelStatus})

	// ControllerRunsDuration the duration of the controller process in seconds
	ControllerRunsDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: Namespace,
		Name:      "controllers_runs_duration_seconds",
		Help:      "Duration in seconds of the controller process labeled by completion status",
	}, []string{LabelStatus})

	// BuildQueueEntries is the number of queued, waiting and running
	// builds in the build queue
	BuildQueueEntries = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "buildqueue_entries",
		Help:      "The number of queued, waiting and running builds in the build queue",
	}, []string{LabelBuildState, LabelBuildQueueName})

	// subprocess, labeled by Subsystem
	SubprocessStart = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "subprocess_start_total",
		Help:      "Number of times that Cilium has started a subprocess, labeled by subsystem",
	}, []string{LabelSubsystem})

	// Kubernetes Events

	// KubernetesEvent is the number of Kubernetes events received labeled by
	// scope, action and execution result
	KubernetesEvent = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "kubernetes_events_total",
		Help:      "Number of Kubernetes events received labeled by scope, action and execution result",
	}, []string{LabelScope, LabelAction, LabelStatus})

	// IPAM events

	// IpamEvent is the number of IPAM events received labeled by action and
	// datapath family type
	IpamEvent = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "ipam_events_total",
		Help:      "Number of IPAM events received labeled by action and datapath family type",
	}, []string{LabelAction, LabelDatapathFamily})

	// KVstore events

	// KVStoreOperationsTotal is the  number of interactions with the Key-Value
	// Store, labeled by subsystem, kind of action and action
	KVStoreOperationsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kvstore_operations_total",
		Help: "Number of interactions with the Key-Value Store, labeled by subsystem, kind of action and action",
	}, []string{LabelScope, LabelKind, LabelAction})
)

func init() {
	MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{Namespace: "cilium"}))
	// TODO: Figure out how to put this into a Namespace
	//MustRegister(prometheus.NewGoCollector())

	MustRegister(EndpointCountRegenerating)
	MustRegister(EndpointRegenerationCount)
	MustRegister(EndpointRegenerationTime)
	MustRegister(EndpointRegenerationTimeSquare)
	MustRegister(EndpointStateCount)
	MustRegister(EndpointRegenerationTimeStats)

	MustRegister(PolicyCount)
	MustRegister(PolicyRegenerationCount)
	MustRegister(PolicyRegenerationTime)
	MustRegister(PolicyRegenerationTimeSquare)
	MustRegister(PolicyRevision)
	MustRegister(PolicyImportErrors)
	MustRegister(PolicyEndpointStatus)

	MustRegister(EventTSK8s)
	MustRegister(EventTSContainerd)
	MustRegister(EventTSAPI)

	MustRegister(ProxyRedirects)
	MustRegister(ProxyParseErrors)
	MustRegister(ProxyForwarded)
	MustRegister(ProxyDenied)
	MustRegister(ProxyReceived)
	MustRegister(ProxyUpstreamTime)

	MustRegister(DropCount)
	MustRegister(DropBytes)
	MustRegister(ForwardCount)
	MustRegister(ForwardBytes)

	MustRegister(newStatusCollector())

	MustRegister(DatapathErrors)
	MustRegister(ConntrackGCRuns)
	MustRegister(ConntrackGCKeyFallbacks)
	MustRegister(ConntrackGCSize)
	MustRegister(ConntrackGCDuration)

	MustRegister(ServicesCount)

	MustRegister(ErrorsWarnings)

	MustRegister(ControllerRuns)
	MustRegister(ControllerRunsDuration)

	MustRegister(BuildQueueEntries)

	MustRegister(SubprocessStart)

	MustRegister(KubernetesEvent)

	MustRegister(IpamEvent)

	MustRegister(KVStoreOperationsTotal)
}

// MustRegister adds the collector to the registry, exposing this metric to
// prometheus scrapes.
// It will panic on error.
func MustRegister(c prometheus.Collector) {
	registry.MustRegister(c)
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
		http.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
		errs <- http.ListenAndServe(addr, nil)
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
