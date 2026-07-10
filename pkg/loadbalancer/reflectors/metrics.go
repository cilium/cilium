// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflectors

import "github.com/cilium/cilium/pkg/loadbalancer"

type SVCMetrics interface {
	AddService(svc *loadbalancer.Service)
	DelService(svc *loadbalancer.Service)
}

type svcMetricsNoop struct {
}

func (s svcMetricsNoop) AddService(svc *loadbalancer.Service) {
}

func (s svcMetricsNoop) DelService(svc *loadbalancer.Service) {
}

func NewSVCMetricsNoop() SVCMetrics {
	return &svcMetricsNoop{}
}
