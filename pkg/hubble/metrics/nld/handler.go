// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package nld

import (
	"context"
	"slices"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	"github.com/cilium/cilium/pkg/identity"
)

const (
	nldLabel        = "k8s:k8s-app=node-local-dns"
	systemNamespace = "kube-system"
	queryLabel      = "dnsQuery"
	responseLabel   = "dnsReponse"
	dnsPort         = 53
)

type nldHandler struct {
	includeDirection bool
	ignoreHost       bool

	context *api.ContextOptions

	upstream   *prometheus.CounterVec
	downstream *prometheus.CounterVec
	bypass     *prometheus.CounterVec
}

func (d *nldHandler) Init(registry *prometheus.Registry, options api.Options) error {
	c, err := api.ParseContextOptions(options)
	if err != nil {
		return err
	}
	d.context = c

	for key := range options {
		switch strings.ToLower(key) {
		case "direction":
			d.includeDirection = true
		case "ignoreHost":
			d.ignoreHost = true
		}
	}

	contextLabels := d.context.GetLabelNames()
	var directionLabel []string
	if d.includeDirection {
		directionLabel = []string{"direction"}
	}

	finalLabels := append(contextLabels, directionLabel...)

	d.downstream = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "nld_downstream_total",
		Help:      "Number of observed DNS queries from workloads to the Node Local DNS Cache",
	}, finalLabels)
	registry.MustRegister(d.downstream)

	d.upstream = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "nld_upstream_total",
		Help:      "Number of observed DNS queries from the Node Local DNS Cache to the upstream",
	}, finalLabels)
	registry.MustRegister(d.upstream)

	d.bypass = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "nld_bypass_total",
		Help:      "Number of observed DNS queries not going through the Node Local DNS Cache",
	}, finalLabels)
	registry.MustRegister(d.bypass)

	return nil
}

func (d *nldHandler) Status() string {
	var status []string
	if d.includeDirection {
		status = append(status, "includeDirection")
	}
	if d.ignoreHost {
		status = append(status, "ignoreHost")
	}

	return strings.Join(append(status, d.context.Status()), ",")
}

func (d *nldHandler) Context() *api.ContextOptions {
	return d.context
}

func (d *nldHandler) ListMetricVec() []*prometheus.MetricVec {
	return []*prometheus.MetricVec{d.upstream.MetricVec, d.downstream.MetricVec, d.bypass.MetricVec}
}

func (d *nldHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) error {
	if flow.GetVerdict() != flowpb.Verdict_FORWARDED || flow.GetL4() == nil {
		return nil
	}

	if d.ignoreHost && isHostTraffic(flow) {
		return nil
	}

	isDNSQuery := checkDestinationPort(flow.GetL4())
	isDNSResponse := checkSourcePort(flow.GetL4())
	if !(isDNSQuery || isDNSResponse) {
		return nil
	}

	contextLabels, err := d.context.GetLabelValues(flow)
	if err != nil {
		return err
	}

	var directionLabel []string
	if d.includeDirection && isDNSQuery {
		directionLabel = []string{queryLabel}
	}
	if d.includeDirection && isDNSResponse {
		directionLabel = []string{responseLabel}
	}

	finalLabels := append(contextLabels, directionLabel...)

	srcnld := isNodeLocalDNSPod(flow.Source)
	dstnld := isNodeLocalDNSPod(flow.Destination)

	switch {
	case !srcnld && !dstnld:
		d.bypass.WithLabelValues(finalLabels...).Inc()
	case !srcnld && dstnld && isDNSQuery:
		d.downstream.WithLabelValues(finalLabels...).Inc()
	case srcnld && !dstnld && isDNSResponse:
		d.downstream.WithLabelValues(finalLabels...).Inc()
	case !srcnld && dstnld && isDNSResponse:
		d.upstream.WithLabelValues(finalLabels...).Inc()
	case srcnld && !dstnld && isDNSQuery:
		d.upstream.WithLabelValues(finalLabels...).Inc()
	}

	return nil
}

func checkDestinationPort(l4 *flowpb.Layer4) bool {
	if l4.GetUDP().GetDestinationPort() == dnsPort {
		return true
	}
	if l4.GetTCP().GetDestinationPort() == dnsPort {
		return true
	}
	return false
}

func checkSourcePort(l4 *flowpb.Layer4) bool {
	if l4.GetUDP().GetSourcePort() == dnsPort {
		return true
	}
	if l4.GetTCP().GetSourcePort() == dnsPort {
		return true
	}
	return false
}

func isNodeLocalDNSPod(endpoint *flowpb.Endpoint) bool {
	return endpoint.GetNamespace() == systemNamespace && slices.Contains(endpoint.Labels, nldLabel)
}

func isHostTraffic(flow *flowpb.Flow) bool {
	return flow.GetSource().GetIdentity() == uint32(identity.ReservedIdentityHost) ||
		flow.GetDestination().GetIdentity() == uint32(identity.ReservedIdentityHost)
}
