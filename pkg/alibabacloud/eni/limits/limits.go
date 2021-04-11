// Copyright 2021 Authors of Cilium
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

package limits

import (
	"context"

	openapi "github.com/cilium/cilium/pkg/alibabacloud/api"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"
)

// limits contains limits for adapter count and addresses. The mappings will be
// updated from agent configuration at bootstrap time.
//
// Source: https://www.alibabacloud.com/help/doc-detail/25378.htm
var limits = struct {
	lock.RWMutex

	m map[string]ipamTypes.Limits
}{
	m: map[string]ipamTypes.Limits{},
}

// Update update the limit map
func Update(limitMap map[string]ipamTypes.Limits) {
	limits.Lock()
	defer limits.Unlock()

	for k, v := range limitMap {
		limits.m[k] = v
	}
}

// Get returns the instance limits of a particular instance type.
func Get(instanceType string) (limit ipamTypes.Limits, ok bool) {
	limits.RLock()
	limit, ok = limits.m[instanceType]
	limits.RUnlock()
	return
}

// UpdateFromAPI updates limits for instance
// https://www.alibabacloud.com/help/doc-detail/25620.htm
func UpdateFromAPI(ctx context.Context, ecs *openapi.Client) error {
	instanceTypeInfos, err := ecs.GetInstanceTypes(ctx)
	if err != nil {
		return err
	}

	limits.Lock()
	defer limits.Unlock()

	for _, instanceTypeInfo := range instanceTypeInfos {
		instanceType := instanceTypeInfo.InstanceTypeId
		adapterLimit := instanceTypeInfo.EniQuantity
		ipv4PerAdapter := instanceTypeInfo.EniPrivateIpAddressQuantity
		ipv6PerAdapter := instanceTypeInfo.EniIpv6AddressQuantity

		limits.m[instanceType] = ipamTypes.Limits{
			Adapters: adapterLimit,
			IPv4:     ipv4PerAdapter,
			IPv6:     ipv6PerAdapter,
		}
	}

	return nil
}
