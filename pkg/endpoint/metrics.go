// Copyright 2016-2018 Authors of Cilium
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

package endpoint

import (
	"time"

	"github.com/cilium/cilium/pkg/metrics"
)

const (
	labelEndpointRegenerationBPFCompilation = "bpf-compilation"
	labelEndpointProxyConfiguration         = "proxy-configuration"
	labelEndpointRegenerationTotal          = "total"
)

// regenerationMetric is a helper function to update metrics.EndpointRegenerationTime
func regenerationMetric(scope string, duration time.Duration) {
	metrics.EndpointRegenerationTime.With(map[string]string{
		metrics.LabelScope: scope,
	}).Observe(duration.Seconds())
	return
}

// metricsEndpointRegenerationBPF is a helper function to update
// metrics.EndpointRegenerationTime with label BPF.
func (e *Endpoint) metricsEndpointRegenerationBPF(duration time.Duration) {
	regenerationMetric(labelEndpointRegenerationBPFCompilation, duration)
}

// metricsEndpointRegenerationProxyConfiguration is a helper function to update
// metrics.EndpointRegenerationTime with label proxy-configuration.
func (e *Endpoint) metricsEndpointRegenerationProxyConfiguration(duration time.Duration) {
	regenerationMetric(labelEndpointProxyConfiguration, duration)
}

// metricsEndpointRegenerationTotal is a helper function to update
// metrics.EndpointRegenerationTime with label total.
func (e *Endpoint) metricsEndpointRegenerationTotal(duration time.Duration) {
	regenerationMetric(labelEndpointRegenerationTotal, duration)
}
