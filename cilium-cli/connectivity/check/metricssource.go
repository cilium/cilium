// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"fmt"

	"github.com/cilium/cilium/pkg/components"
)

const prometheusContainerPortName = "prometheus"

// MetricsSource defines the info for a source to be used in metrics collection.
type MetricsSource struct {
	Name string // the name of the source, e.g.: cilium-agent
	Pods []Pod  // the list of pods for the given source
	Port string // the container port value for prometheus
}

// IsEmpty returns if the metrics source name is empty,
// assuming it MetricsSource is set to its zero value.
func (m MetricsSource) IsEmpty() bool {
	return m.Name == ""
}

// CiliumAgentMetrics returns the MetricsSource for the cilium-agent component.
func (ct *ConnectivityTest) CiliumAgentMetrics() MetricsSource {
	ciliumPods := ct.CiliumPods()
	if len(ciliumPods) == 0 {
		return MetricsSource{}
	}

	source := MetricsSource{
		Name: components.CiliumAgentName,
	}

	// Retrieve the container port value for Prometheus.
	for _, p := range ciliumPods {
		source.Pods = append(source.Pods, p)
		// parse all the containers
		for _, c := range p.Pod.Spec.Containers {
			if c.Name == components.CiliumAgentName {
				// parse all the container ports
				for _, port := range c.Ports {
					if port.Name == prometheusContainerPortName {
						source.Port = fmt.Sprintf("%d", port.ContainerPort)
						break
					}
				}
			}
		}
	}

	// Prometheus port was not find, let's return an empty MetricsSource.
	if source.Port == "" {
		return MetricsSource{}
	}

	return source
}
