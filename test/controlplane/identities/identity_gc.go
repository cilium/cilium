// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identities

import (
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/cidr"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/test/controlplane"
	"github.com/cilium/cilium/test/controlplane/suite"
)

var (
	initialObjects = []k8sRuntime.Object{
		&corev1.Node{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Node",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:   "identity-control-plane",
				Labels: map[string]string{"kubernetes.io/hostname": "identity-control-plane"},
			},
			Spec: corev1.NodeSpec{
				PodCIDR:  cidr.MustParseCIDR("10.244.0.0/24").String(),
				PodCIDRs: []string{cidr.MustParseCIDR("10.244.0.0/24").String()},
				Taints: []corev1.Taint{
					{Effect: corev1.TaintEffectNoSchedule, Key: "node-role.kubernetes.io/control-plane"},
				},
			},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{},
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeInternalIP, Address: "172.18.0.3"},
					{Type: corev1.NodeHostName, Address: "identity-control-plane"},
				},
			},
		},
		&corev1.Node{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Node",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:   "identity-worker",
				Labels: map[string]string{"kubernetes.io/hostname": "identity-worker"},
			},
			Spec: corev1.NodeSpec{
				PodCIDR:  cidr.MustParseCIDR("10.244.1.0/24").String(),
				PodCIDRs: []string{cidr.MustParseCIDR("10.244.1.0/24").String()},
			},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{},
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeInternalIP, Address: "172.18.0.2"},
					{Type: corev1.NodeHostName, Address: "identity-worker"},
				},
			},
		},
	}

	dummyIdentity = &v2.CiliumIdentity{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "cilium.io/v2",
			Kind:       "CiliumIdentity",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "99999",
			Labels: map[string]string{
				"io.cilium.k8s.policy.cluster":        "default",
				"io.cilium.k8s.policy.serviceaccount": "default",
				"io.kubernetes.pod.namespace":         "default",
				"foo":                                 "bar",
			},
		},
		SecurityLabels: map[string]string{
			"k8s:io.cilium.k8s.policy.cluster":        "default",
			"k8s:io.cilium.k8s.policy.serviceaccount": "default",
			"k8s:io.kubernetes.pod.namespace":         "default",
			"k8s:foo":                                 "bar",
		},
	}
)

func applyDummyIdentity(test *suite.ControlPlaneTest) error {
	test.UpdateObjects(dummyIdentity)

	if _, err := test.Get(
		schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumidentities"},
		"",
		dummyIdentity.Name,
	); err != nil {
		return fmt.Errorf("unable to find CiliumIdentity %q: %w", dummyIdentity.Name, err)
	}

	return nil
}

func validateIdentityGC(test *suite.ControlPlaneTest) error {
	_, err := test.Get(
		schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumidentities"},
		"",
		dummyIdentity.Name,
	)

	if err == nil {
		return fmt.Errorf("unexpectedly found CiliumIdentity %q after GC", dummyIdentity.Name)
	}

	if !errors.IsNotFound(err) {
		return fmt.Errorf("unexpected error while searching for CiliumIdentity %q: %w", dummyIdentity.Name, err)
	}

	return nil
}

func init() {
	suite.AddTestCase("IdentityGC", func(t *testing.T) {
		k8sVersions := controlplane.K8sVersions()
		// We only need to test the last k8s version
		test := suite.NewControlPlaneTest(t, "identity-control-plane", k8sVersions[len(k8sVersions)-1])

		defer test.StopAgent()
		defer test.StopOperator()

		modConfig := func(_ *option.DaemonConfig, operatorCfg *operatorOption.OperatorConfig) {
			operatorCfg.EndpointGCInterval = 2 * time.Second
			operatorCfg.IdentityGCInterval = 2 * time.Second
			operatorCfg.IdentityHeartbeatTimeout = 2 * time.Second
		}

		test.
			UpdateObjects(initialObjects...).
			SetupEnvironment(modConfig).
			StartAgent().
			StartOperator().
			Execute(func() error { return applyDummyIdentity(test) }).
			Eventually(func() error { return validateIdentityGC(test) })
	})
}
