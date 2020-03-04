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

package portdistribution

import (
	"fmt"

	pb "github.com/cilium/hubble/api/v1/flow"
	"github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/hubble/pkg/metrics/api"

	"github.com/prometheus/client_golang/prometheus"
)

type portDistributionHandler struct {
	portDistribution *prometheus.CounterVec
	context          *api.ContextOptions
}

func (h *portDistributionHandler) Init(registry *prometheus.Registry, options api.Options) error {
	c, err := api.ParseContextOptions(options)
	if err != nil {
		return err
	}
	h.context = c

	labels := []string{"protocol", "port"}
	labels = append(labels, h.context.GetLabelNames()...)

	h.portDistribution = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "port_distribution_total",
		Help:      "Numbers of packets distributed by destination port",
	}, labels)

	registry.MustRegister(h.portDistribution)
	return nil
}

func (h *portDistributionHandler) Status() string {
	return h.context.Status()
}

func (h *portDistributionHandler) ProcessFlow(flow v1.Flow) {
	if flow.GetVerdict() != pb.Verdict_FORWARDED || flow.GetL4() == nil || flow.GetReply() {
		return
	}

	if tcp := flow.GetL4().GetTCP(); tcp != nil {
		labels := append([]string{"TCP", fmt.Sprintf("%d", tcp.DestinationPort)}, h.context.GetLabelValues(flow)...)
		h.portDistribution.WithLabelValues(labels...).Inc()
	}

	if udp := flow.GetL4().GetUDP(); udp != nil {
		labels := append([]string{"UDP", fmt.Sprintf("%d", udp.DestinationPort)}, h.context.GetLabelValues(flow)...)
		h.portDistribution.WithLabelValues(labels...).Inc()
	}

	if flow.GetL4().GetICMPv4() != nil {
		labels := append([]string{"ICMPv4", "0"}, h.context.GetLabelValues(flow)...)
		h.portDistribution.WithLabelValues(labels...).Inc()
	}

	if flow.GetL4().GetICMPv6() != nil {
		labels := append([]string{"ICMPv6", "0"}, h.context.GetLabelValues(flow)...)
		h.portDistribution.WithLabelValues(labels...).Inc()
	}
}
