// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type proxyMetrics struct {
	// ProxyRedirects is the number of redirects labeled by protocol
	ProxyRedirects metric.Vec[metric.Gauge]
}

// LabelProtocolL7 is the label used when working with layer 7 protocols.
const LabelProtocolL7 = "protocol_l7"

func newProxyMetrics() *proxyMetrics {
	return &proxyMetrics{
		ProxyRedirects: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: metrics.Namespace + "_proxy_redirects",

			Namespace: metrics.Namespace,
			Name:      "proxy_redirects",
			Help:      "Number of redirects installed for endpoints, labeled by protocol",
		}, []string{LabelProtocolL7}),
	}
}
