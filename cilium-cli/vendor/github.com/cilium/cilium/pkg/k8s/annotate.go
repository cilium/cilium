// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type nodeAnnotation = map[string]string

var nodeAnnotationControllerGroup = controller.NewGroup("update-k8s-node-annotations")

func prepareNodeAnnotation(nd nodeTypes.Node, encryptKey uint8) nodeAnnotation {
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

func updateNodeAnnotation(c kubernetes.Interface, nodeName string, annotation nodeAnnotation) error {
	if len(annotation) == 0 {
		return nil
	}

	raw, err := json.Marshal(annotation)
	if err != nil {
		return err
	}
	patch := []byte(fmt.Sprintf(`{"metadata":{"annotations":%s}}`, raw))

	_, err = c.CoreV1().Nodes().Patch(context.TODO(), nodeName, types.StrategicMergePatchType, patch, metav1.PatchOptions{}, "status")

	return err
}

// AnnotateNode writes v4 and v6 CIDRs and health IPs in the given k8s node name.
// In case of failure while updating the node, this function while spawn a go
// routine to retry the node update indefinitely.
func AnnotateNode(cs kubernetes.Interface, nodeName string, nd nodeTypes.Node, encryptKey uint8) (nodeAnnotation, error) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.NodeName:       nodeName,
		logfields.V4Prefix:       nd.IPv4AllocCIDR,
		logfields.V6Prefix:       nd.IPv6AllocCIDR,
		logfields.V4HealthIP:     nd.IPv4HealthIP,
		logfields.V6HealthIP:     nd.IPv6HealthIP,
		logfields.V4IngressIP:    nd.IPv4IngressIP,
		logfields.V6IngressIP:    nd.IPv6IngressIP,
		logfields.V4CiliumHostIP: nd.GetCiliumInternalIP(false),
		logfields.V6CiliumHostIP: nd.GetCiliumInternalIP(true),
		logfields.Key:            encryptKey,
	})
	scopedLog.Debug("Updating node annotations with node CIDRs")
	annotation := prepareNodeAnnotation(nd, encryptKey)
	controller.NewManager().UpdateController("update-k8s-node-annotations",
		controller.ControllerParams{
			Group: nodeAnnotationControllerGroup,
			DoFunc: func(_ context.Context) error {
				err := updateNodeAnnotation(cs, nodeName, annotation)
				if err != nil {
					scopedLog.WithFields(logrus.Fields{}).WithError(err).Warn("Unable to patch node resource with annotation")
				}
				return err
			},
		})

	return annotation, nil
}

func prepareRemoveNodeAnnotationsPayload(annotation nodeAnnotation) ([]byte, error) {
	deleteAnnotations := []JSONPatch{}

	for key := range annotation {
		deleteAnnotations = append(deleteAnnotations, JSONPatch{
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
	return strings.Replace(element, "/", "~1", -1)
}
