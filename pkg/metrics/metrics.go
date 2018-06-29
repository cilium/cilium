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

// Package metrics holds prometheus metrics objects and related utility functions. It
// does not abstract away the prometheus client but the caller rarely needs to
// refer to prometheus directly.
package metrics

// Adding a metric
// - Add a metric object of the appropriate type as an exported variable
// - Register the new object in the init function

import (
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	log "github.com/sirupsen/logrus"
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

	// EndpointStateCount is the total count of the endpoints in various states.
	EndpointStateCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "endpoint_state",
			Help:      "Count of all endpoints, tagged by different endpoint states",
		},
		[]string{"endpoint_state"},
	)

	// Policy

	// PolicyCount is the number of policies loaded into the agent
	PolicyCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "policy_count",
		Help:      "Number of policies currently loaded",
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

	// L3-L4 statistics

	// DropCount is the total drop requests,
	// tagged by drop reason and direction(ingress/egress)
	DropCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "drop_count_total",
		Help:      "Total dropped packets, tagged by drop reason and ingress/egress direction",
	},
		[]string{"reason", "direction"})

	// ForwardCount is the total forward requests,
	// tagged by ingress/egress direction
	ForwardCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "forward_count_total",
		Help:      "Total forwarded packets, tagged by ingress/egress direction",
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
	},
		[]string{LabelDatapathArea, LabelDatapathName, LabelDatapathFamily})
)

func init() {
	MustRegister(prometheus.NewProcessCollector(os.Getpid(), Namespace))
	// TODO: Figure out how to put this into a Namespace
	//MustRegister(prometheus.NewGoCollector())

	MustRegister(EndpointCountRegenerating)
	MustRegister(EndpointRegenerationCount)
	MustRegister(EndpointStateCount)

	MustRegister(PolicyCount)
	MustRegister(PolicyRevision)
	MustRegister(PolicyImportErrors)

	MustRegister(EventTSK8s)
	MustRegister(EventTSContainerd)
	MustRegister(EventTSAPI)

	MustRegister(ProxyParseErrors)
	MustRegister(ProxyForwarded)
	MustRegister(ProxyDenied)
	MustRegister(ProxyReceived)

	MustRegister(DropCount)
	MustRegister(ForwardCount)

	MustRegister(newStatusCollector())

	MustRegister(DatapathErrors)
}

// MustRegister adds the collector to the registry, exposing this metric to
// prometheus scrapes.
// It will panic on error.
func MustRegister(c prometheus.Collector) {
	registry.MustRegister(c)
}

// Enable begins serving prometheus metrics on the address passed in. Addresses
// of the form ":8080" will bind the port on all interfaces.
func Enable(addr string) error {
	go func() {
		// The Handler function provides a default handler to expose metrics
		// via an HTTP server. "/metrics" is the usual endpoint for that.
		http.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
		log.WithError(http.ListenAndServe(addr, nil)).Warn("Cannot start metrics server on %s", addr)
	}()

	return nil
}

// SetTSValue sets the gauge to the time value provided
func SetTSValue(c prometheus.Gauge, ts time.Time) {
	// Build time in seconds since the epoch. Prometheus only takes floating
	// point values, however, and urges times to be in seconds
	c.Set(float64(ts.UnixNano()) / float64(1000000000))
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
