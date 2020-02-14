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

package tcp

import (
	pb "github.com/cilium/hubble/api/v1/flow"
	"github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/hubble/pkg/metrics/api"

	"github.com/prometheus/client_golang/prometheus"
)

type tcpHandler struct {
	tcpFlags *prometheus.CounterVec
	context  *api.ContextOptions
}

func (h *tcpHandler) Init(registry *prometheus.Registry, options api.Options) error {
	c, err := api.ParseContextOptions(options)
	if err != nil {
		return err
	}
	h.context = c

	labels := []string{"flag", "family"}
	labels = append(labels, h.context.GetLabelNames()...)

	h.tcpFlags = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "tcp_flags_total",
		Help:      "TCP flag occurences",
	}, labels)

	registry.MustRegister(h.tcpFlags)
	return nil
}

func (h *tcpHandler) Status() string {
	return h.context.Status()
}

func (h *tcpHandler) ProcessFlow(flow v1.Flow) {
	if flow.GetVerdict() != pb.Verdict_FORWARDED || flow.GetL4() == nil {
		return
	}

	ip := flow.GetIP()
	tcp := flow.GetL4().GetTCP()
	if ip == nil || tcp == nil || tcp.Flags == nil {
		return
	}

	labels := append([]string{"", ip.IpVersion.String()}, h.context.GetLabelValues(flow)...)

	if tcp.Flags.FIN {
		labels[0] = "FIN"
		h.tcpFlags.WithLabelValues(labels...).Inc()
	}

	if tcp.Flags.SYN {
		if tcp.Flags.ACK {
			labels[0] = "SYN-ACK"
			h.tcpFlags.WithLabelValues(labels...).Inc()
		} else {
			labels[0] = "SYN"
			h.tcpFlags.WithLabelValues(labels...).Inc()
		}
	}

	if tcp.Flags.RST {
		labels[0] = "RST"
		h.tcpFlags.WithLabelValues(labels...).Inc()
	}
}
