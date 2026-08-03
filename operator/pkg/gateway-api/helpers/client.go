// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ClientReader is the narrowest controller-runtime client surface needed by
// Gateway API input loading and related indexers. It intentionally excludes all
// write methods so those paths remain read-only at compile time.
type ClientReader interface {
	client.Reader
	Scheme() *runtime.Scheme
}
