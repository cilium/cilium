// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package dns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type dnsHandler struct {
	includeQuery bool
	ignoreAAAA   bool

	context   *api.ContextOptions
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
	err = h.HandleConfigurationUpdate(options)
	if err != nil {
		return err
	}

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

	if !filters.Apply(h.AllowList, h.DenyList, &v1.Event{Event: flow, Timestamp: &timestamppb.Timestamp{}}) {
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

func (h *dnsHandler) Deinit(registry *prometheus.Registry) error {
	var errs error
	if !registry.Unregister(h.queries) {
		errs = errors.Join(errs, fmt.Errorf("failed to unregister metric: %v,", "dns_queries_total"))
	}
	if !registry.Unregister(h.responses) {
		errs = errors.Join(errs, fmt.Errorf("failed to unregister metric: %v,", "dns_responses_total"))
	}
	if !registry.Unregister(h.responseTypes) {
		errs = errors.Join(errs, fmt.Errorf("failed to unregister metric: %v,", "dns_response_types_total"))
	}
	return errs
}

func (h *dnsHandler) HandleConfigurationUpdate(cfg *api.MetricConfig) error {
	return h.SetFilters(cfg)
}

func (h *dnsHandler) SetFilters(cfg *api.MetricConfig) error {
	var err error
	h.AllowList, err = filters.BuildFilterList(context.Background(), cfg.IncludeFilters, filters.DefaultFilters(slog.Default()))
	if err != nil {
		return err
	}
	h.DenyList, err = filters.BuildFilterList(context.Background(), cfg.ExcludeFilters, filters.DefaultFilters(slog.Default()))
	if err != nil {
		return err
	}
	return nil
}
