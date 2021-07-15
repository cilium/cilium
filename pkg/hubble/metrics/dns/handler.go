// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 Authors of Hubble

package dns

import (
	"context"
	"fmt"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"

	"github.com/prometheus/client_golang/prometheus"
)

type dnsHandler struct {
	includeQuery bool
	ignoreAAAA   bool

	context *api.ContextOptions

	queries       *prometheus.CounterVec
	responses     *prometheus.CounterVec
	responseTypes *prometheus.CounterVec
}

func (d *dnsHandler) Init(registry *prometheus.Registry, options api.Options) error {
	c, err := api.ParseContextOptions(options)
	if err != nil {
		return err
	}
	d.context = c

	for key := range options {
		switch strings.ToLower(key) {
		case "query":
			d.includeQuery = true
		case "ignoreaaaa":
			d.ignoreAAAA = true
		}
	}

	labels := []string{"rcode", "qtypes", "ips_returned"}
	if d.includeQuery {
		labels = append(labels, "query")
	}

	labels = append(labels, d.context.GetLabelNames()...)

	d.queries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "dns_queries_total",
		Help:      "Number of DNS queries observed",
	}, labels)
	registry.MustRegister(d.queries)

	d.responses = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "dns_responses_total",
		Help:      "Number of DNS queries observed",
	}, labels)
	registry.MustRegister(d.responses)

	labels = []string{"type", "qtypes"}
	if d.includeQuery {
		labels = append(labels, "query")
	}
	labels = append(labels, d.context.GetLabelNames()...)
	d.responseTypes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "dns_response_types_total",
		Help:      "Number of DNS queries observed",
	}, labels)
	registry.MustRegister(d.responseTypes)

	return nil
}

func (d *dnsHandler) Status() string {
	var status []string
	if d.includeQuery {
		status = append(status, "query")
	}
	if d.ignoreAAAA {
		status = append(status, "ignoreAAAA")
	}

	return strings.Join(append(status, d.context.Status()), ",")
}

func (d *dnsHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) {
	if flow.GetL7() == nil {
		return
	}

	dns := flow.GetL7().GetDns()
	if dns == nil {
		return
	}

	if d.ignoreAAAA && len(dns.Qtypes) == 1 && dns.Qtypes[0] == "AAAA" {
		return
	}

	labelValues := d.context.GetLabelValues(flow)
	labels := []string{"", strings.Join(dns.Qtypes, ","), fmt.Sprintf("%d", len(dns.Ips))}
	if d.includeQuery {
		labels = append(labels, dns.Query)
	}
	labels = append(labels, labelValues...)

	if flow.GetVerdict() == flowpb.Verdict_DROPPED {
		d.queries.WithLabelValues(labels...).Inc()
		labels[0] = "Policy denied"
		d.responses.WithLabelValues(labels...).Inc()
	} else {
		if flow.GetIsReply().GetValue() {
			labels[0] = rcodeNames[dns.Rcode]
			d.responses.WithLabelValues(labels...).Inc()

			if len(dns.Rrtypes) > 0 {
				labels := []string{"", strings.Join(dns.Qtypes, ",")}
				if d.includeQuery {
					labels = append(labels, dns.Query)
				}
				labels = append(labels, d.context.GetLabelValues(flow)...)

				for _, t := range dns.Rrtypes {
					labels[0] = t
					d.responseTypes.WithLabelValues(labels...).Inc()
				}
			}
		} else {
			d.queries.WithLabelValues(labels...).Inc()
		}
	}
}
