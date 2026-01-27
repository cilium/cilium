// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	// Subsystem is the metrics subsystem for ztunnel XDS
	subsystem = "ztunnel"

	// Label names
	labelStatus = "status"
)

// Metrics holds XDS-related metrics
type Metrics struct {
	// CertificateIssuanceFailures tracks certificate issuance failures from Spire
	// Status values: success, csr_empty, csr_invalid, csr_parse_failed, signature_failed,
	// uri_invalid, scheme_invalid, spiffe_malformed, sa_not_found, cert_creation_failed
	CertificateIssuanceFailures metric.Vec[metric.Counter]
}

// NewMetrics creates a new Metrics instance
func NewMetrics() *Metrics {
	return &Metrics{
		CertificateIssuanceFailures: metric.NewCounterVec(
			metric.CounterOpts{
				Namespace: metrics.Namespace,
				Subsystem: subsystem,
				Name:      "certificate_issuance_failures_total",
				Help:      "Total number of certificate issuance failures from Spire by status (success, csr_empty, csr_invalid, csr_parse_failed, signature_failed, uri_invalid, scheme_invalid, spiffe_malformed, sa_not_found, cert_creation_failed)",
			},
			[]string{labelStatus},
		),
	}
}
