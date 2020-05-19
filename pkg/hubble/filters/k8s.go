// Copyright 2019-2020 Authors of Hubble
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

package filters

import (
	"context"
	"fmt"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/k8s"
)

func sourcePod(ev *v1.Event) (ns, pod string) {
	ep := ev.GetFlow().GetSource()
	return ep.GetNamespace(), ep.GetPodName()
}

func destinationPod(ev *v1.Event) (ns, pod string) {
	ep := ev.GetFlow().GetDestination()
	return ep.GetNamespace(), ep.GetPodName()
}

func sourceService(ev *v1.Event) (ns, svc string) {
	s := ev.GetFlow().GetSourceService()
	return s.GetNamespace(), s.GetName()
}

func destinationService(ev *v1.Event) (ns, svc string) {
	s := ev.GetFlow().GetDestinationService()
	return s.GetNamespace(), s.GetName()
}

func filterByNamespacedName(names []string, getName func(*v1.Event) (ns, name string)) (FilterFunc, error) {
	type nameFilter struct{ ns, prefix string }
	nameFilters := make([]nameFilter, 0, len(names))
	for _, name := range names {
		ns, prefix := k8s.ParseNamespaceName(name)
		if ns == "" && prefix == "" {
			return nil, fmt.Errorf("invalid filter, must be [namespace/][<name>], got %q", name)
		}
		nameFilters = append(nameFilters, nameFilter{ns, prefix})
	}

	return func(ev *v1.Event) bool {
		eventNs, eventName := getName(ev)
		if eventNs == "" && eventName == "" {
			return false
		}

		for _, f := range nameFilters {
			if (f.prefix == "" || strings.HasPrefix(eventName, f.prefix)) && f.ns == eventNs {
				return true
			}
		}

		return false
	}, nil
}

// PodFilter implements filtering based on Kubernetes pod names
type PodFilter struct{}

// OnBuildFilter builds a Kubernetes pod name filter
func (p *PodFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetSourcePod() != nil {
		pf, err := filterByNamespacedName(ff.GetSourcePod(), sourcePod)
		if err != nil {
			return nil, err
		}
		fs = append(fs, pf)
	}

	if ff.GetDestinationPod() != nil {
		pf, err := filterByNamespacedName(ff.GetDestinationPod(), destinationPod)
		if err != nil {
			return nil, err
		}
		fs = append(fs, pf)
	}

	return fs, nil
}

// ServiceFilter implements filtering based on Kubernetes service names
type ServiceFilter struct{}

// OnBuildFilter builds a Kubernetes service name filter
func (s *ServiceFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetSourceService() != nil {
		ssf, err := filterByNamespacedName(ff.GetSourceService(), sourceService)
		if err != nil {
			return nil, fmt.Errorf("invalid source service filter: %v", err)
		}
		fs = append(fs, ssf)
	}

	if ff.GetDestinationService() != nil {
		dsf, err := filterByNamespacedName(ff.GetDestinationService(), destinationService)
		if err != nil {
			return nil, fmt.Errorf("invalid destination service filter: %v", err)
		}
		fs = append(fs, dsf)
	}

	return fs, nil
}
