// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumnetworkpolicies

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	operatorApi "github.com/cilium/cilium/operator/api"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/cidr"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/test/controlplane"
	"github.com/cilium/cilium/test/controlplane/suite"
)

var (
	dummyCNP = &v2.CiliumNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "cilium.io/v2",
			Kind:       "CiliumNetworkPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cnp-status-update-policy",
			Namespace: "cnp-status-update-namespace",
			UID:       k8sTypes.UID("39668ba4-eb30-4e35-baa0-4db34aa639ad"),
		},
		Spec: &api.Rule{
			EndpointSelector: api.EndpointSelector{
				LabelSelector: &v1.LabelSelector{
					MatchLabels: map[string]string{
						"foo": "bar",
					},
				},
			},
		},
		Status: v2.CiliumNetworkPolicyStatus{
			Nodes: map[string]v2.CiliumNetworkPolicyNodeStatus{
				"cnp-status-update-control-plane": {
					Enforcing:   true,
					LastUpdated: v1.Time{Time: time.Now()},
					Revision:    2,
					OK:          true,
				},
				"cnp-status-update-worker": {
					Enforcing:   true,
					LastUpdated: v1.Time{Time: time.Now()},
					Revision:    2,
					OK:          true,
				},
			},
		},
	}

	dummyCCNP = &v2.CiliumClusterwideNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "cilium.io/v2",
			Kind:       "CiliumClusterwideNetworkPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cnp-status-update-policy",
			UID:  k8sTypes.UID("39668ba4-eb30-4e35-baa0-4db34aa639ad"),
		},
		Spec: &api.Rule{
			EndpointSelector: api.EndpointSelector{
				LabelSelector: &v1.LabelSelector{
					MatchLabels: map[string]string{
						"foo": "bar",
					},
				},
			},
		},
		Status: v2.CiliumNetworkPolicyStatus{
			Nodes: map[string]v2.CiliumNetworkPolicyNodeStatus{
				"cnp-status-update-control-plane": {
					Enforcing:   true,
					LastUpdated: v1.Time{Time: time.Now()},
					Revision:    2,
					OK:          true,
				},
				"cnp-status-update-worker": {
					Enforcing:   true,
					LastUpdated: v1.Time{Time: time.Now()},
					Revision:    2,
					OK:          true,
				},
			},
		},
	}

	initialObjects = []k8sRuntime.Object{
		&corev1.Node{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Node",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:   "cnp-status-update-control-plane",
				Labels: map[string]string{"kubernetes.io/hostname": "cnp-status-update-control-plane"},
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
					{Type: corev1.NodeHostName, Address: "cnp-status-update-control-plane"},
				},
			},
		},
		&corev1.Node{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Node",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:   "cnp-status-update-worker",
				Labels: map[string]string{"kubernetes.io/hostname": "cnp-status-update-worker"},
			},
			Spec: corev1.NodeSpec{
				PodCIDR:  cidr.MustParseCIDR("10.244.1.0/24").String(),
				PodCIDRs: []string{cidr.MustParseCIDR("10.244.1.0/24").String()},
			},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{},
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeInternalIP, Address: "172.18.0.2"},
					{Type: corev1.NodeHostName, Address: "cnp-status-update-worker"},
				},
			},
		},
		dummyCNP,
		dummyCCNP,
	}
)

func getDummyCNP(test *suite.ControlPlaneTest) (*v2.CiliumNetworkPolicy, error) {
	cnpObj, err := test.Get(
		schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"},
		dummyCNP.Namespace,
		dummyCNP.Name,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to find CiliumNetworkPolicy %s/%s: %w", dummyCNP.Namespace, dummyCNP.Name, err)
	}

	cnp, ok := cnpObj.(*v2.CiliumNetworkPolicy)
	if !ok {
		return nil, errors.New("type assertion failed for CNP obj")
	}

	return cnp, nil
}

func getDummyCCNP(test *suite.ControlPlaneTest) (*v2.CiliumClusterwideNetworkPolicy, error) {
	ccnpObj, err := test.Get(
		schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumclusterwidenetworkpolicies"},
		"",
		dummyCCNP.Name,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to find CiliumClusterwideNetworkPolicy %s: %w", dummyCCNP.Name, err)
	}

	ccnp, ok := ccnpObj.(*v2.CiliumClusterwideNetworkPolicy)
	if !ok {
		return nil, errors.New("type assertion failed for CCNP obj")
	}

	return ccnp, nil
}

func validateCNPs(test *suite.ControlPlaneTest) error {
	cnp, err := getDummyCNP(test)
	if err != nil {
		return err
	}
	if len(cnp.Status.Nodes) != len(dummyCNP.Status.Nodes) {
		return fmt.Errorf("number of updates in CNP Status Nodes should be: %d, found: %d", len(dummyCNP.Status.Nodes), len(cnp.Status.Nodes))
	}

	ccnp, err := getDummyCCNP(test)
	if err != nil {
		return err
	}
	if len(ccnp.Status.Nodes) != len(dummyCCNP.Status.Nodes) {
		return fmt.Errorf("number of updates in CCNP Status Nodes should be: %d, found: %d", len(dummyCCNP.Status.Nodes), len(ccnp.Status.Nodes))
	}

	return nil
}

func validateCNPsAfterGC(test *suite.ControlPlaneTest) error {
	cnp, err := getDummyCNP(test)
	if err != nil {
		return err
	}
	if len(cnp.Status.Nodes) != 0 {
		return fmt.Errorf(
			"unexpected updates in CiliumNetworkPolicy %s/%s Status Nodes found after GC: %v",
			dummyCNP.Namespace,
			dummyCNP.Name,
			cnp.Status.Nodes,
		)
	}

	ccnp, err := getDummyCCNP(test)
	if err != nil {
		return err
	}
	if len(ccnp.Status.Nodes) != 0 {
		return fmt.Errorf(
			"unexpected updates in CiliumClusterwideNetworkPolicy %s Status Nodes found after GC: %v",
			dummyCCNP.Name,
			cnp.Status.Nodes,
		)
	}

	return nil
}

func init() {
	suite.AddTestCase("CNPStatusNodesGC", func(t *testing.T) {
		k8sVersions := controlplane.K8sVersions()
		// We only need to test the last k8s version
		test := suite.NewControlPlaneTest(t, "cnp-status-update-control-plane", k8sVersions[len(k8sVersions)-1])

		// When running with GC disabled, the Nodes Status updates should not be deleted.
		test.
			UpdateObjects(initialObjects...).
			SetupEnvironment(func(_ *option.DaemonConfig, operatorCfg *operatorOption.OperatorConfig) {
				operatorCfg.SkipCNPStatusStartupClean = true
			}).
			// check that CNPs contain status updates info before starting agent and operator
			Eventually(func() error { return validateCNPs(test) }).
			StartAgent().
			StartOperator(func(vp *viper.Viper) {
				vp.Set(operatorApi.OperatorAPIServeAddr, "localhost:0")
			}).
			Eventually(func() error { return validateCNPs(test) })

		test.StopAgent()
		test.StopOperator()
		test.DeleteObjects(initialObjects...)

		// When running with GC enabled, the Nodes Status updates should eventually be deleted.
		test.
			UpdateObjects(initialObjects...).
			SetupEnvironment(func(_ *option.DaemonConfig, operatorCfg *operatorOption.OperatorConfig) {
				operatorCfg.SkipCNPStatusStartupClean = false
			}).
			// check that CNPs contain status updates info before starting agent and operator
			Eventually(func() error { return validateCNPs(test) }).
			StartAgent().
			StartOperator(func(vp *viper.Viper) {
				vp.Set(operatorApi.OperatorAPIServeAddr, "localhost:0")
			}).
			Eventually(func() error { return validateCNPsAfterGC(test) })

		test.StopAgent()
		test.StopOperator()
	})
}
