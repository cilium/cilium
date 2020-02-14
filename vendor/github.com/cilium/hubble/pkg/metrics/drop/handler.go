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

package drop

import (
	pb "github.com/cilium/hubble/api/v1/flow"
	"github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/hubble/pkg/metrics/api"

	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/prometheus/client_golang/prometheus"
)

type dropHandler struct {
	drops   *prometheus.CounterVec
	context *api.ContextOptions
}

func (d *dropHandler) Init(registry *prometheus.Registry, options api.Options) error {
	c, err := api.ParseContextOptions(options)
	if err != nil {
		return err
	}
	d.context = c

	labels := []string{"reason", "protocol"}
	labels = append(labels, d.context.GetLabelNames()...)

	d.drops = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "drop_total",
		Help:      "Number of drops",
	}, labels)

	registry.MustRegister(d.drops)
	return nil
}

func (d *dropHandler) Status() string {
	return d.context.Status()
}

func (d *dropHandler) ProcessFlow(flow v1.Flow) {
	if flow.GetVerdict() != pb.Verdict_DROPPED {
		return
	}

	labels := []string{monitorAPI.DropReason(uint8(flow.GetDropReason())), v1.FlowProtocol(flow)}
	labels = append(labels, d.context.GetLabelValues(flow)...)

	d.drops.WithLabelValues(labels...).Inc()
}
