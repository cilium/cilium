// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package dns

import (
	"context"
	"fmt"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type dnsHandler struct {
	includeQuery bool
	ignoreAAAA   bool

	context   *api.ContextOptions
	cfg       *api.MetricConfig
	AllowList filters.FilterFuncs
	DenyList  filters.FilterFuncs

	queries       *prometheus.CounterVec
	responses     *prometheus.CounterVec
	responseTypes *prometheus.CounterVec
}

func (h *dnsHandler) Init(registry *prometheus.Registry, options *api.MetricConfig) error {
	c, err := api.ParseContextOptions(options.ContextOptionConfigs)
	if err != nil {
		return err
	}
	h.context = c
	h.cfg = options
	// TODO use global logger
	h.AllowList, err = filters.BuildFilterList(context.Background(), h.cfg.IncludeFilters, filters.DefaultFilters(logrus.New()))
	h.DenyList, err = filters.BuildFilterList(context.Background(), h.cfg.ExcludeFilters, filters.DefaultFilters(logrus.New()))

	for _, opt := range options.ContextOptionConfigs {
		switch strings.ToLower(opt.Name) {
		case "query":
			h.includeQuery = true
		case "ignoreaaaa":
			h.ignoreAAAA = true
		}
	}

	contextLabels := h.context.GetLabelNames()
	commonLabels := append(contextLabels, "rcode", "qtypes")
	queryAndResponseLabels := append(commonLabels, "ips_returned")
	responseTypeLabels := append(contextLabels, "type", "qtypes")

	if h.includeQuery {
		queryAndResponseLabels = append(queryAndResponseLabels, "query")
		responseTypeLabels = append(responseTypeLabels, "query")
	}

	h.queries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "dns_queries_total",
		Help:      "Number of DNS queries observed",
	}, queryAndResponseLabels)
	registry.MustRegister(h.queries)

	h.responses = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "dns_responses_total",
		Help:      "Number of DNS queries observed",
	}, queryAndResponseLabels)
	registry.MustRegister(h.responses)

	h.responseTypes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "dns_response_types_total",
		Help:      "Number of DNS queries observed",
	}, responseTypeLabels)
	registry.MustRegister(h.responseTypes)

	return nil
}

func (h *dnsHandler) Status() string {
	var status []string
	if h.includeQuery {
		status = append(status, "query")
	}
	if h.ignoreAAAA {
		status = append(status, "ignoreAAAA")
	}

	return strings.Join(append(status, h.context.Status()), ",")
}

func (h *dnsHandler) Context() *api.ContextOptions {
	return h.context
}

func (h *dnsHandler) ListMetricVec() []*prometheus.MetricVec {
	return []*prometheus.MetricVec{h.queries.MetricVec, h.responses.MetricVec, h.responseTypes.MetricVec}
}

func (h *dnsHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) error {
	if flow.GetL7() == nil {
		return nil
	}

	dns := flow.GetL7().GetDns()
	if dns == nil {
		return nil
	}

	if h.ignoreAAAA && len(dns.Qtypes) == 1 && dns.Qtypes[0] == "AAAA" {
		return nil
	}

	contextLabels, err := h.context.GetLabelValues(flow)
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
		if h.includeQuery {
			labels = append(labels, dns.Query)
		}
		h.queries.WithLabelValues(labels...).Inc()
	case !flow.GetIsReply().GetValue(): // dns request
		labels := append(contextLabels, rcode, qtypes, ipsReturned)
		if h.includeQuery {
			labels = append(labels, dns.Query)
		}
		h.queries.WithLabelValues(labels...).Inc()
	case flow.GetIsReply().GetValue(): // dns response
		rcode = rcodeNames[dns.Rcode]
		labels := append(contextLabels, rcode, qtypes, ipsReturned)
		if h.includeQuery {
			labels = append(labels, dns.Query)
		}
		h.responses.WithLabelValues(labels...).Inc()

		for _, responseType := range dns.Rrtypes {
			newLabels := append(contextLabels, responseType, qtypes)
			if h.includeQuery {
				newLabels = append(newLabels, dns.Query)
			}
			h.responseTypes.WithLabelValues(newLabels...).Inc()
		}
	}

	return nil
}

func (h *dnsHandler) Deinit(registry *prometheus.Registry) {
	registry.Unregister(h.queries)
	registry.Unregister(h.responses)
	registry.Unregister(h.responseTypes)
}
