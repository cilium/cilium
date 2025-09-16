// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"strings"
	"time"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

func watchCiliumNodes(ctx context.Context, ciliumNodes resource.Resource[*cilium_v2.CiliumNode], handler allocator.NodeEventHandler, withResync bool) {
	// We will use CiliumNodes as the source of truth for the podCIDRs.
	// Once the CiliumNodes are synchronized with the operator we will
	// be able to watch for K8s Node events which they will be used
	// to create the remaining CiliumNodes.
	for ev := range ciliumNodes.Events(ctx) {
		switch ev.Kind {
		case resource.Upsert:
			value, ok := ev.Object.Annotations[annotation.IPAMIgnore]
			if !ok || strings.ToLower(value) != "true" {
				handler.Upsert(ev.Object)
			}

		case resource.Delete:
			handler.Delete(ev.Object)

		case resource.Sync:
			// We don't want CiliumNodes that don't have podCIDRs to be
			// allocated with a podCIDR already being used by another node.
			// For this reason we will call Resync after all CiliumNodes are
			// synced with the operator to signal the node manager, since it
			// knows all podCIDRs that are currently set in the cluster, that
			// it can allocate podCIDRs for the nodes that don't have a podCIDR
			// set.
			if withResync {
				handler.Resync(ctx, time.Time{})
			}
		}

		ev.Done(nil)
	}
}

type ciliumNodeUpdateImplementation struct {
	clientset k8sClient.Clientset
}

func (c *ciliumNodeUpdateImplementation) Create(node *cilium_v2.CiliumNode) (*cilium_v2.CiliumNode, error) {
	return c.clientset.CiliumV2().CiliumNodes().Create(context.TODO(), node, meta_v1.CreateOptions{})
}

func (c *ciliumNodeUpdateImplementation) Get(node string) (*cilium_v2.CiliumNode, error) {
	return c.clientset.CiliumV2().CiliumNodes().Get(context.TODO(), node, meta_v1.GetOptions{})
}

func (c *ciliumNodeUpdateImplementation) UpdateStatus(origNode, node *cilium_v2.CiliumNode) (*cilium_v2.CiliumNode, error) {
	if origNode == nil || !origNode.Status.DeepEqual(&node.Status) {
		return c.clientset.CiliumV2().CiliumNodes().UpdateStatus(context.TODO(), node, meta_v1.UpdateOptions{})
	}
	return nil, nil
}

func (c *ciliumNodeUpdateImplementation) Update(origNode, node *cilium_v2.CiliumNode) (*cilium_v2.CiliumNode, error) {
	if origNode == nil || !origNode.Spec.DeepEqual(&node.Spec) {
		return c.clientset.CiliumV2().CiliumNodes().Update(context.TODO(), node, meta_v1.UpdateOptions{})
	}
	return nil, nil
}
