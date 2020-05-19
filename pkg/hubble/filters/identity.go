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

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func sourceEndpoint(ev *v1.Event) *flowpb.Endpoint {
	return ev.GetFlow().GetSource()
}

func destinationEndpoint(ev *v1.Event) *flowpb.Endpoint {
	return ev.GetFlow().GetDestination()
}

func filterByIdentity(identities []uint32, getEndpoint func(*v1.Event) *flowpb.Endpoint) FilterFunc {
	return func(ev *v1.Event) bool {
		if endpoint := getEndpoint(ev); endpoint != nil {
			for _, i := range identities {
				if i == endpoint.Identity {
					return true
				}
			}
		}
		return false
	}
}

// IdentityFilter implements filtering based on security identity
type IdentityFilter struct{}

// OnBuildFilter builds a security identity filter
func (i *IdentityFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetSourceIdentity() != nil {
		fs = append(fs, filterByIdentity(ff.GetSourceIdentity(), sourceEndpoint))
	}

	if ff.GetDestinationIdentity() != nil {
		fs = append(fs, filterByIdentity(ff.GetDestinationIdentity(), destinationEndpoint))
	}

	return fs, nil
}
