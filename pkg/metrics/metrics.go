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
	log "github.com/sirupsen/logrus"
)

var (
	registry = prometheus.NewPedanticRegistry()

	// Namespace is used to scope metrics from cilium. It is prepended to metric
	// names and separated with a '_'
	Namespace = "cilium"

	// Labels

	// LabelValueOutcomeSuccess is used as a successful outcome of an operation
	LabelValueOutcomeSuccess = "success"

	// LabelValueOutcomeFail is used as an unsuccessful outcome of an operation
	LabelValueOutcomeFail = "fail"

	// LabelEventSourceAPI marks event-related metrics that come from the API
	LabelEventSourceAPI = "api"

	// LabelEventSourceK8s marks event-related metrics that come from k8s
	LabelEventSourceK8s = "k8s"

	// LabelEventSourceContainerd marks event-related metrics that come from containerd
	LabelEventSourceContainerd = "containerd"

	// Endpoint

	// EndpointCount is the number of managed endpoints
	EndpointCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "endpoint_count",
		Help:      "Number of endpoints managed by this agent",
	})

	// EndpointCountRegenerating is the number of endpoints currently regenerating
	EndpointCountRegenerating = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "endpoint_regenerating",
		Help:      "Number of endpoints currently regenerating",
	})

	// EndpointRegenerationCount is a count of the number of times any endpoint
	// has been regenerated and success/fail outcome
	EndpointRegenerationCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "endpoint_regenerations",
		Help:      "Count of all endpoint regenerations that have completed, tagged by outcome",
	},
		[]string{"outcome"})

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

	// EventTS*is the time in seconds since epoch that we last recieved an
	// event that we will handle
	// source is one of k8s, containerd or apia

	// EventTSK8s is the timestamp of k8s events
	EventTSK8s = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace:   Namespace,
		Name:        "event_ts",
		Help:        "Last timestamp when we received an event",
		ConstLabels: prometheus.Labels{"source": LabelEventSourceK8s},
	})

	// EventTSContainerd is the timestamp of containerd events
	EventTSContainerd = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace:   Namespace,
		Name:        "event_ts",
		Help:        "Last timestamp when we received an event",
		ConstLabels: prometheus.Labels{"source": LabelEventSourceContainerd},
	})

	// EventTSAPI is the timestamp of containerd events
	EventTSAPI = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace:   Namespace,
		Name:        "event_ts",
		Help:        "Last timestamp when we received an event",
		ConstLabels: prometheus.Labels{"source": LabelEventSourceAPI},
	})
)

func init() {
	registry.MustRegister(prometheus.NewProcessCollector(os.Getpid(), Namespace))
	// TODO: Figure out how to put this into a Namespace
	//registry.MustRegister(prometheus.NewGoCollector())

	registry.MustRegister(EndpointCount)
	registry.MustRegister(EndpointCountRegenerating)
	registry.MustRegister(EndpointRegenerationCount)

	registry.MustRegister(PolicyCount)
	registry.MustRegister(PolicyRevision)
	registry.MustRegister(PolicyImportErrors)

	registry.MustRegister(EventTSK8s)
	registry.MustRegister(EventTSContainerd)
	registry.MustRegister(EventTSAPI)
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
