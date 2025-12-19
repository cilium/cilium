// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodediscovery

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type nodeAnnotation = map[string]string

var nodeAnnotationControllerGroup = controller.NewGroup("update-k8s-node-annotations")

func (n *NodeDiscovery) prepareNodeAnnotations(localNode nodeTypes.Node) nodeAnnotation {
	annotationMap := map[string]fmt.Stringer{
		annotation.V4CIDRName:     localNode.IPv4AllocCIDR,
		annotation.V6CIDRName:     localNode.IPv6AllocCIDR,
		annotation.V4HealthName:   localNode.IPv4HealthIP,
		annotation.V6HealthName:   localNode.IPv6HealthIP,
		annotation.V4IngressName:  localNode.IPv4IngressIP,
		annotation.V6IngressName:  localNode.IPv6IngressIP,
		annotation.CiliumHostIP:   localNode.GetCiliumInternalIP(false),
		annotation.CiliumHostIPv6: localNode.GetCiliumInternalIP(true),
	}

	annotations := map[string]string{}
	for k, v := range annotationMap {
		if !reflect.ValueOf(v).IsNil() {
			annotations[k] = v.String()
		}
	}
	if localNode.EncryptionKey != 0 {
		annotations[annotation.CiliumEncryptionKey] = strconv.FormatUint(uint64(localNode.EncryptionKey), 10)
	}
	return annotations
}

func (n *NodeDiscovery) updateNodeAnnotations(ctx context.Context, c kubernetes.Interface, nodeName string, annotation nodeAnnotation) error {
	if len(annotation) == 0 {
		return nil
	}

	raw, err := json.Marshal(annotation)
	if err != nil {
		return err
	}
	patch := fmt.Appendf(nil, `{"metadata":{"annotations":%s}}`, raw)

	_, err = c.CoreV1().Nodes().Patch(ctx, nodeName, k8sTypes.StrategicMergePatchType, patch, metav1.PatchOptions{}, "status")

	return err
}

func (n *NodeDiscovery) AnnotateK8sNode(ctx context.Context) {
	if !n.clientset.IsEnabled() || !n.daemonConfig.AnnotateK8sNode {
		n.logger.Debug("Annotate k8s node is disabled.")
		return
	}

	latestLocalNode, err := n.localNodeStore.Get(ctx)
	if err != nil {
		n.logger.Warn("Cannot get local node", logfields.Error, err)
		return
	}

	n.annotateK8sNode(ctx, n.clientset, latestLocalNode.Node)
}

// annotateK8sNode starts a controller that tries to write local node information into the k8s node resource annotations.
func (n *NodeDiscovery) annotateK8sNode(ctx context.Context, cs kubernetes.Interface, localNode nodeTypes.Node) {
	scopedLog := n.logger.With(
		logfields.NodeName, localNode.Name,
		logfields.V4Prefix, localNode.IPv4AllocCIDR,
		logfields.V6Prefix, localNode.IPv6AllocCIDR,
		logfields.V4HealthIP, localNode.IPv4HealthIP,
		logfields.V6HealthIP, localNode.IPv6HealthIP,
		logfields.V4IngressIP, localNode.IPv4IngressIP,
		logfields.V6IngressIP, localNode.IPv6IngressIP,
		logfields.V4CiliumHostIP, localNode.GetCiliumInternalIP(false),
		logfields.V6CiliumHostIP, localNode.GetCiliumInternalIP(true),
		logfields.Key, localNode.EncryptionKey,
	)
	scopedLog.Info("Annotating k8s Node with node information")

	controller.NewManager().UpdateController("update-k8s-node-annotations",
		controller.ControllerParams{
			Group: nodeAnnotationControllerGroup,
			DoFunc: func(ctx context.Context) error {
				annotations := n.prepareNodeAnnotations(localNode)
				if err := n.updateNodeAnnotations(ctx, cs, localNode.Name, annotations); err != nil {
					scopedLog.Warn("Unable to patch node resource with annotation, retrying", logfields.Error, err)
					return err
				}
				return nil
			},
			Context: ctx,
		})
}
