// Copyright 2020 Authors of Cilium
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

package allocator

import (
	"context"
	"time"

	"github.com/cilium/cilium/pkg/ipam"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// AllocatorProvider defines the functions of IPAM provider front-end
// these are implemented by e.g. pkg/ipam/allocator/{aws,azure}.
type AllocatorProvider interface {
	Init() error
	Start(getterUpdater ipam.CiliumNodeGetterUpdater) (NodeEventHandler, error)
}

// NodeEventHandler should implement the behavior to handle CiliumNode
type NodeEventHandler interface {
	Create(resource *v2.CiliumNode) bool
	Update(resource *v2.CiliumNode) bool
	Delete(nodeName string)
	Resync(context.Context, time.Time)
}
