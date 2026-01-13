// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package allocator

import (
	"context"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/time"
)

// NodeEventHandler should implement the behavior to handle CiliumNode
type NodeEventHandler interface {
	Upsert(resource *v2.CiliumNode)
	Delete(resource *v2.CiliumNode)
	Resync(context.Context, time.Time)
}
