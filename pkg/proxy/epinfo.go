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

package proxy

import (
	"net"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/proxy/logger"
)

var (
	// DefaultEndpointInfoRegistry is the default instance implementing the
	// EndpointInfoRegistry interface.
	DefaultEndpointInfoRegistry logger.EndpointInfoRegistry = &defaultEndpointInfoRegistry{}
)

// defaultEndpointInfoRegistry is the default implementation of the
// EndpointInfoRegistry interface.
type defaultEndpointInfoRegistry struct{}

func (r *defaultEndpointInfoRegistry) FillEndpointIdentityByID(id identity.NumericIdentity, info *accesslog.EndpointInfo) bool {
	identity := cache.LookupIdentityByID(id)
	if identity == nil {
		return false
	}

	info.Identity = uint64(id)
	info.Labels = identity.Labels.GetModel()
	info.LabelsSHA256 = identity.GetLabelsSHA256()

	return true
}

func (r *defaultEndpointInfoRegistry) FillEndpointIdentityByIP(ip net.IP, info *accesslog.EndpointInfo) bool {
	ep := endpointmanager.LookupIP(ip)
	if ep == nil {
		return false
	}

	if err := ep.RLockAlive(); err != nil {
		ep.LogDisconnectedMutexAction(err, "before FillEndpointIdentityByIP")
		return false
	}

	info.ID = uint64(ep.ID)
	info.Identity = uint64(ep.GetIdentity())
	info.Labels = ep.GetLabels()
	info.LabelsSHA256 = ep.GetLabelsSHA()

	ep.RUnlock()
	return true
}
