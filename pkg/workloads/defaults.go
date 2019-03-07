// Copyright 2018 Authors of Cilium
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

package workloads

import (
	"context"
	"time"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"

	k8sLbls "k8s.io/kubernetes/pkg/kubelet/types"
)

const (
	// EndpointCorrelationMaxRetries is the number of retries to correlate
	// a workload start event with an existing endpoint before giving up.
	EndpointCorrelationMaxRetries = 20
)

// EndpointCorrelationSleepTime returns the sleep time between correlation
// attempts
func EndpointCorrelationSleepTime(try int) time.Duration {
	return time.Duration(try) * time.Second
}

func shortContainerID(id string) string {
	if len(id) < 10 {
		return id
	}
	return id[:10]
}

func getFilteredLabels(containerID string, allLabels map[string]string) (identityLabels, informationLabels labels.Labels) {
	combinedLabels := labels.Map2Labels(allLabels, labels.LabelSourceContainer)

	k8sNormalLabels, err := fetchK8sLabels(containerID, allLabels)
	if err != nil {
		log.WithError(err).Warn("Error while getting Kubernetes labels")
	} else if k8sNormalLabels != nil {
		k8sLbls := labels.Map2Labels(k8sNormalLabels, labels.LabelSourceK8s)
		combinedLabels.MergeLabels(k8sLbls)
	}

	return labels.FilterLabels(combinedLabels)
}

func processCreateWorkload(ep *endpoint.Endpoint, containerID string, allLabels map[string]string) {
	ep.SetContainerID(containerID)

	// FIXME: Remove this in 2019-06: GH-6526
	if k8s.IsEnabled() && ep.GetK8sPodName() == "" {
		ep.SetK8sNamespace(k8sLbls.GetPodNamespace(allLabels))
		ep.SetK8sPodName(k8sLbls.GetPodName(allLabels))
	}

	// Update map allowing to lookup endpoint by endpoint
	// attributes with new attributes set on endpoint
	endpointmanager.UpdateReferences(ep)

	identityLabels, informationLabels := getFilteredLabels(containerID, allLabels)
	ep.UpdateLabels(context.Background(), Owner(), identityLabels, informationLabels, false)
}
