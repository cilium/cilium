// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import "github.com/cilium/cilium/pkg/k8s/resource"

func podResourceKey(podName, podNamespace string) resource.Key {
	return resource.Key{Name: podName, Namespace: podNamespace}
}

type PodItem struct {
	key resource.Key
}

func (p PodItem) Key() resource.Key {
	return p.key
}
