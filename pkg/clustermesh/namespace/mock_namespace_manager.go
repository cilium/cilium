// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namespace

import (
	"context"
	"testing"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/k8s"
	k8sFakeClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

// NewMockNamespaceManager creates a Namespace Manager with a fake clientset and the provided namespaces.
func NewMockNamespaceManager(t *testing.T, enableDefaultGlobalNamespace bool, namespaces ...*slim_corev1.Namespace) Manager {
	var (
		log             = hivetest.Logger(t)
		lc              = hivetest.Lifecycle(t)
		cs, _           = k8sFakeClient.NewFakeClientset(log)
		namespaceRes, _ = k8s.NamespaceResource(lc, cs, nil)
	)
	for _, ns := range namespaces {
		_, err := cs.Slim().CoreV1().Namespaces().Create(context.Background(), ns, v1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	return newManager(managerParams{
		Logger:     log,
		Lifecycle:  lc,
		Namespaces: namespaceRes,
		Config: Config{
			EnableDefaultGlobalNamespace: enableDefaultGlobalNamespace,
		},
	})
}
