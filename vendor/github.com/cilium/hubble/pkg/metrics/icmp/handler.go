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

package icmp

import (
	"github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/hubble/pkg/metrics/api"

	"github.com/google/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"
)

type icmpHandler struct {
	icmp    *prometheus.CounterVec
	context *api.ContextOptions
}

func (h *icmpHandler) Init(registry *prometheus.Registry, options api.Options) error {
	c, err := api.ParseContextOptions(options)
	if err != nil {
		return err
	}
	h.context = c

	labels := []string{"family", "type"}
	labels = append(labels, h.context.GetLabelNames()...)

	h.icmp = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "icmp_total",
		Help:      "Number of ICMP messages",
	}, labels)

	registry.MustRegister(h.icmp)
	return nil
}

func (h *icmpHandler) Status() string {
	return h.context.Status()
}

func (h *icmpHandler) ProcessFlow(flow v1.Flow) {
	l4 := flow.GetL4()
	if l4 == nil {
		return
	}

	if icmp := l4.GetICMPv4(); icmp != nil {
		labels := []string{"IPv4", layers.CreateICMPv4TypeCode(uint8(icmp.Type), uint8(icmp.Code)).String()}
		labels = append(labels, h.context.GetLabelValues(flow)...)
		h.icmp.WithLabelValues(labels...).Inc()
	}

	if icmp := l4.GetICMPv6(); icmp != nil {
		labels := []string{"IPv4", layers.CreateICMPv6TypeCode(uint8(icmp.Type), uint8(icmp.Code)).String()}
		labels = append(labels, h.context.GetLabelValues(flow)...)
		h.icmp.WithLabelValues(labels...).Inc()
	}
}
