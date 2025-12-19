// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodediscovery

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type nodeAnnotation = map[string]string

var nodeAnnotationControllerGroup = controller.NewGroup("update-k8s-node-annotations")

func (n *NodeDiscovery) prepareNodeAnnotation(nd nodeTypes.Node, encryptKey uint8) nodeAnnotation {
	annotationMap := map[string]fmt.Stringer{
		annotation.V4CIDRName:     nd.IPv4AllocCIDR,
		annotation.V6CIDRName:     nd.IPv6AllocCIDR,
		annotation.V4HealthName:   nd.IPv4HealthIP,
		annotation.V6HealthName:   nd.IPv6HealthIP,
		annotation.V4IngressName:  nd.IPv4IngressIP,
		annotation.V6IngressName:  nd.IPv6IngressIP,
		annotation.CiliumHostIP:   nd.GetCiliumInternalIP(false),
		annotation.CiliumHostIPv6: nd.GetCiliumInternalIP(true),
	}

	annotations := map[string]string{}
	for k, v := range annotationMap {
		if !reflect.ValueOf(v).IsNil() {
			annotations[k] = v.String()
		}
	}
	if encryptKey != 0 {
		annotations[annotation.CiliumEncryptionKey] = strconv.FormatUint(uint64(encryptKey), 10)
	}
	return annotations
}

func (n *NodeDiscovery) updateNodeAnnotation(c kubernetes.Interface, nodeName string, annotation nodeAnnotation) error {
	if len(annotation) == 0 {
		return nil
	}

	raw, err := json.Marshal(annotation)
	if err != nil {
		return err
	}
	patch := fmt.Appendf(nil, `{"metadata":{"annotations":%s}}`, raw)

	_, err = c.CoreV1().Nodes().Patch(context.TODO(), nodeName, k8sTypes.StrategicMergePatchType, patch, metav1.PatchOptions{}, "status")

	return err
}

func (n *NodeDiscovery) AnnotateK8sNode(ctx context.Context, ipsecSPI uint8) error {
	if !n.clientset.IsEnabled() || !n.daemonConfig.AnnotateK8sNode {
		n.logger.Debug("Annotate k8s node is disabled.")
		return nil
	}

	latestLocalNode, err := n.localNodeStore.Get(ctx)
	if err != nil {
		n.logger.Warn("Cannot get local node", logfields.Error, err)
		return nil
	}

	if _, err = n.annotateK8sNode(n.clientset, nodeTypes.GetName(), latestLocalNode.Node, ipsecSPI); err != nil {
		n.logger.Warn("Cannot annotate k8s node with CIDR range", logfields.Error, err)
		return nil
	}

	return nil
}

// annotateK8sNode writes v4 and v6 CIDRs and health IPs in the given k8s node name.
// In case of failure while updating the node, this function while spawn a go
// routine to retry the node update indefinitely.
func (n *NodeDiscovery) annotateK8sNode(cs kubernetes.Interface, nodeName string, localNode nodeTypes.Node, encryptKey uint8) (nodeAnnotation, error) {
	scopedLog := n.logger.With(
		logfields.NodeName, nodeName,
		logfields.V4Prefix, localNode.IPv4AllocCIDR,
		logfields.V6Prefix, localNode.IPv6AllocCIDR,
		logfields.V4HealthIP, localNode.IPv4HealthIP,
		logfields.V6HealthIP, localNode.IPv6HealthIP,
		logfields.V4IngressIP, localNode.IPv4IngressIP,
		logfields.V6IngressIP, localNode.IPv6IngressIP,
		logfields.V4CiliumHostIP, localNode.GetCiliumInternalIP(false),
		logfields.V6CiliumHostIP, localNode.GetCiliumInternalIP(true),
		logfields.Key, encryptKey,
	)
	scopedLog.Info("Annotating k8s Node with node information")

	annotation := n.prepareNodeAnnotation(localNode, encryptKey)
	controller.NewManager().UpdateController("update-k8s-node-annotations",
		controller.ControllerParams{
			Group: nodeAnnotationControllerGroup,
			DoFunc: func(_ context.Context) error {
				err := n.updateNodeAnnotation(cs, nodeName, annotation)
				if err != nil {
					scopedLog.Warn("Unable to patch node resource with annotation", logfields.Error, err)
				}
				return err
			},
		})

	return annotation, nil
}

func prepareRemoveNodeAnnotationsPayload(annotation nodeAnnotation) ([]byte, error) {
	deleteAnnotations := []k8s.JSONPatch{}

	for key := range annotation {
		deleteAnnotations = append(deleteAnnotations, k8s.JSONPatch{
			OP:   "remove",
			Path: "/metadata/annotations/" + encodeJsonElement(key),
		})
	}

	return json.Marshal(deleteAnnotations)
}

func RemoveNodeAnnotations(c kubernetes.Interface, nodeName string, annotation nodeAnnotation) error {
	patch, err := prepareRemoveNodeAnnotationsPayload(annotation)
	if err != nil {
		return err
	}
	_, err = c.CoreV1().Nodes().Patch(context.TODO(), nodeName, k8sTypes.JSONPatchType, patch, metav1.PatchOptions{}, "status")
	return err
}

func encodeJsonElement(element string) string {
	return strings.ReplaceAll(element, "/", "~1")
}
