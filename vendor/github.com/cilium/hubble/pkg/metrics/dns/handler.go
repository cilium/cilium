// Copyright 2019 Authors of Hubble
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

package dns

import (
	"fmt"
	"strings"

	pb "github.com/cilium/hubble/api/v1/flow"
	"github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/hubble/pkg/metrics/api"

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

func (d *dnsHandler) ProcessFlow(flow v1.Flow) {
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

	if flow.GetVerdict() == pb.Verdict_DROPPED {
		d.queries.WithLabelValues(labels...).Inc()
		labels[0] = "Policy denied"
		d.responses.WithLabelValues(labels...).Inc()
	} else {
		if flow.GetReply() {
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
