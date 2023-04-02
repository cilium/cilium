// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package dns

import (
	"context"
	"fmt"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
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

	contextLabels := d.context.GetLabelNames()
	commonLabels := append(contextLabels, "rcode", "qtypes")
	queryAndResponseLabels := append(commonLabels, "ips_returned")
	responseTypeLabels := append(contextLabels, "type", "qtypes")

	if d.includeQuery {
		queryAndResponseLabels = append(queryAndResponseLabels, "query")
		responseTypeLabels = append(responseTypeLabels, "query")
	}

	d.queries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "dns_queries_total",
		Help:      "Number of DNS queries observed",
	}, queryAndResponseLabels)
	registry.MustRegister(d.queries)

	d.responses = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "dns_responses_total",
		Help:      "Number of DNS queries observed",
	}, queryAndResponseLabels)
	registry.MustRegister(d.responses)

	d.responseTypes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "dns_response_types_total",
		Help:      "Number of DNS queries observed",
	}, responseTypeLabels)
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

func (d *dnsHandler) Context() *api.ContextOptions {
	return d.context
}

func (d *dnsHandler) ListMetricVec() []*prometheus.MetricVec {
	return []*prometheus.MetricVec{d.queries.MetricVec, d.responses.MetricVec, d.responseTypes.MetricVec}
}

func (d *dnsHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) error {
	if flow.GetL7() == nil {
		return nil
	}

	dns := flow.GetL7().GetDns()
	if dns == nil {
		return nil
	}

	if d.ignoreAAAA && len(dns.Qtypes) == 1 && dns.Qtypes[0] == "AAAA" {
		return nil
	}

	contextLabels, err := d.context.GetLabelValues(flow)
	if err != nil {
		return err
	}

	rcode := ""
	qtypes := strings.Join(dns.Qtypes, ",")
	ipsReturned := fmt.Sprintf("%d", len(dns.Ips))

	switch {
	case flow.GetVerdict() == flowpb.Verdict_DROPPED:
		rcode = "Policy denied"
		labels := append(contextLabels, rcode, qtypes, ipsReturned)
		if d.includeQuery {
			labels = append(labels, dns.Query)
		}
		d.queries.WithLabelValues(labels...).Inc()
	case !flow.GetIsReply().GetValue(): // dns request
		labels := append(contextLabels, rcode, qtypes, ipsReturned)
		if d.includeQuery {
			labels = append(labels, dns.Query)
		}
		d.queries.WithLabelValues(labels...).Inc()
	case flow.GetIsReply().GetValue(): // dns response
		rcode = rcodeNames[dns.Rcode]
		labels := append(contextLabels, rcode, qtypes, ipsReturned)
		if d.includeQuery {
			labels = append(labels, dns.Query)
		}
		d.responses.WithLabelValues(labels...).Inc()

		for _, responseType := range dns.Rrtypes {
			newLabels := append(contextLabels, responseType, qtypes)
			if d.includeQuery {
				newLabels = append(newLabels, dns.Query)
			}
			d.responseTypes.WithLabelValues(newLabels...).Inc()
		}
	}

	return nil
}
