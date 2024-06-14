// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import "github.com/cilium/cilium/pkg/k8s/resource"

func cidResourceKey(cidName string) resource.Key {
	return resource.Key{Name: cidName}
}
