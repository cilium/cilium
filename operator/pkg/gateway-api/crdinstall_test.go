// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextfake "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	k8sTesting "k8s.io/client-go/testing"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/pkg/gateway-api/crds"
	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/pkg/k8s/apis"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/time"
)

const testCRDName = "httproutes.gateway.networking.k8s.io"

func newVersionedCRD(version, channel string, managed bool) *apiextensionsv1.CustomResourceDefinition {
	crd := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:        testCRDName,
			Annotations: map[string]string{},
			Labels:      map[string]string{},
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "gateway.networking.k8s.io",
			Names: apiextensionsv1.CustomResourceDefinitionNames{Plural: "httproutes", Kind: "HTTPRoute"},
			Scope: apiextensionsv1.NamespaceScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{
				Name: "v1", Served: true, Storage: true,
				Schema: &apiextensionsv1.CustomResourceValidation{
					OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{Type: "object", Description: version + "/" + channel},
				},
			}},
		},
		Status: apiextensionsv1.CustomResourceDefinitionStatus{
			Conditions: []apiextensionsv1.CustomResourceDefinitionCondition{
				{Type: apiextensionsv1.Established, Status: apiextensionsv1.ConditionTrue},
			},
		},
	}
	if version != "" {
		crd.Annotations[crds.BundleVersionAnnotation] = version
	}
	if channel != "" {
		crd.Annotations[crds.ChannelAnnotation] = channel
	}
	if managed {
		crd.Labels[crdManagedByLabel] = crdManagedByValue
	}
	return crd
}

func TestClassifyCRD(t *testing.T) {
	target := newVersionedCRD("v1.6.1", crds.ChannelStandard, true)

	tests := []struct {
		name    string
		current *apiextensionsv1.CustomResourceDefinition
		want    crdAction
	}{
		{"managed, same version", newVersionedCRD("v1.6.1", crds.ChannelStandard, true), crdActionUpToDate},
		{"managed, older patch", newVersionedCRD("v1.6.0", crds.ChannelStandard, true), crdActionUpgrade},
		{"managed, older minor", newVersionedCRD("v1.5.1", crds.ChannelStandard, true), crdActionUpgrade},
		{"managed, older release candidate", newVersionedCRD("v1.6.1-rc.1", crds.ChannelStandard, true), crdActionUpgrade},
		{"managed, newer is not downgraded", newVersionedCRD("v1.7.0", crds.ChannelStandard, true), crdActionNewer},
		{"managed, unknown version", newVersionedCRD("", crds.ChannelStandard, true), crdActionUpgrade},
		{"managed, invalid version", newVersionedCRD("main", crds.ChannelStandard, true), crdActionUpgrade},
		{"managed label but experimental, newer", newVersionedCRD("v1.7.0", crds.ChannelExperimental, true), crdActionExternal},
		{"managed label but experimental, same", newVersionedCRD("v1.6.1", crds.ChannelExperimental, true), crdActionExternal},
		{"managed label but experimental, older is never switched to standard", newVersionedCRD("v1.5.0", crds.ChannelExperimental, true), crdActionConflict},
		{"managed label but no channel", newVersionedCRD("v1.5.0", "", true), crdActionConflict},
		{"external, same version", newVersionedCRD("v1.6.1", crds.ChannelStandard, false), crdActionExternal},
		{"external, newer", newVersionedCRD("v1.7.0", crds.ChannelStandard, false), crdActionExternal},
		{"external experimental, same version", newVersionedCRD("v1.6.1", crds.ChannelExperimental, false), crdActionExternal},
		{"external, older", newVersionedCRD("v1.5.1", crds.ChannelStandard, false), crdActionConflict},
		{"external experimental, older", newVersionedCRD("v1.4.0", crds.ChannelExperimental, false), crdActionConflict},
		{"external, no annotations", newVersionedCRD("", "", false), crdActionConflict},
		{"external, other managed-by value", func() *apiextensionsv1.CustomResourceDefinition {
			crd := newVersionedCRD("v1.5.0", crds.ChannelStandard, false)
			crd.Labels[crdManagedByLabel] = "Helm"
			return crd
		}(), crdActionConflict},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := classifyCRD(target, tt.current)
			require.NoError(t, err)
			require.Equal(t, tt.want, got.action, got.reason)
			if got.action != crdActionUpToDate {
				require.NotEmpty(t, got.reason)
			}
		})
	}

	_, err := classifyCRD(newVersionedCRD("", crds.ChannelStandard, true), target)
	require.Error(t, err, "target CRD without version must be rejected")
}

func TestBundledCRDs(t *testing.T) {
	targets, err := bundledCRDs()
	require.NoError(t, err)
	require.NotEmpty(t, targets)
	upstream, err := crds.Standard()
	require.NoError(t, err)
	for i, crd := range targets {
		require.Equal(t, crdManagedByValue, crd.Labels[crdManagedByLabel])
		// Upstream labels (e.g. gateway.networking.k8s.io/policy) are retained.
		for k, v := range upstream[i].Labels {
			require.Equal(t, v, crd.Labels[k])
		}
	}

	// All the kinds required by Cilium must be part of the bundle.
	var gvks []schema.GroupVersionKind
	for _, crd := range targets {
		for _, v := range crd.Spec.Versions {
			if v.Served {
				gvks = append(gvks, schema.GroupVersionKind{Group: crd.Spec.Group, Version: v.Name, Kind: crd.Spec.Names.Plural})
			}
		}
	}
	for _, gvk := range helpers.RequiredGVKs {
		require.Contains(t, gvks, gvk)
	}
}

// newFakeAPIExtClientset returns a fake apiextensions clientset in which
// created CRDs are immediately established, and a function returning the
// CRD write actions performed so far.
func newFakeAPIExtClientset(objs ...runtime.Object) (*apiextfake.Clientset, func() []k8sTesting.Action) {
	cs := apiextfake.NewSimpleClientset(objs...)
	cs.PrependReactor("create", "customresourcedefinitions", func(action k8sTesting.Action) (bool, runtime.Object, error) {
		crd := action.(k8sTesting.CreateAction).GetObject().(*apiextensionsv1.CustomResourceDefinition)
		crd.Status.Conditions = append(crd.Status.Conditions, apiextensionsv1.CustomResourceDefinitionCondition{
			Type: apiextensionsv1.Established, Status: apiextensionsv1.ConditionTrue,
		})
		return false, nil, nil
	})
	writes := func() []k8sTesting.Action {
		var out []k8sTesting.Action
		for _, a := range cs.Actions() {
			switch a.GetVerb() {
			case "create", "update", "patch", "delete", "delete-collection":
				out = append(out, a)
			}
		}
		return out
	}
	return cs, writes
}

func getCRD(t *testing.T, cs *apiextfake.Clientset, name string) *apiextensionsv1.CustomResourceDefinition {
	t.Helper()
	crd, err := cs.ApiextensionsV1().CustomResourceDefinitions().Get(t.Context(), name, metav1.GetOptions{})
	require.NoError(t, err)
	return crd
}

func installTestCRDs(t *testing.T, cs *apiextfake.Clientset, targets []*apiextensionsv1.CustomResourceDefinition) (error, *cell.SimpleHealth) {
	t.Helper()
	health, simpleHealth := cell.NewSimpleHealth()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	return installCRDs(ctx, hivetest.Logger(t), cs, health, targets), simpleHealth
}

func TestInstallCRDs_FreshClusterAndIdempotency(t *testing.T) {
	targets, err := bundledCRDs()
	require.NoError(t, err)
	cs, writes := newFakeAPIExtClientset()

	err, health := installTestCRDs(t, cs, targets)
	require.NoError(t, err)
	require.Equal(t, cell.StatusOK, health.Level)
	require.Len(t, writes(), len(targets))
	for _, target := range targets {
		crd := getCRD(t, cs, target.Name)
		require.Equal(t, crdManagedByValue, crd.Labels[crdManagedByLabel])
		require.Equal(t, target.Annotations[crds.BundleVersionAnnotation], crd.Annotations[crds.BundleVersionAnnotation])
		require.Equal(t, crds.ChannelStandard, crd.Annotations[crds.ChannelAnnotation])
		require.Equal(t, target.Spec, crd.Spec)
	}

	// Simulate an operator restart: nothing must be written anymore.
	targets, err = bundledCRDs()
	require.NoError(t, err)
	cs.ClearActions()
	err, health = installTestCRDs(t, cs, targets)
	require.NoError(t, err)
	require.Equal(t, cell.StatusOK, health.Level)
	require.Empty(t, writes())
}

func TestInstallCRDs_ExistingCRDs(t *testing.T) {
	target := newVersionedCRD("v1.6.1", crds.ChannelStandard, true)

	tests := []struct {
		name          string
		current       *apiextensionsv1.CustomResourceDefinition
		expectUpdate  bool
		expectHealthy bool
	}{
		{
			name:          "externally managed compatible CRD is not taken over",
			current:       newVersionedCRD("v1.6.1", crds.ChannelStandard, false),
			expectHealthy: true,
		},
		{
			name:          "externally managed experimental CRD is not switched to standard",
			current:       newVersionedCRD("v1.7.0", crds.ChannelExperimental, false),
			expectHealthy: true,
		},
		{
			name:    "externally managed older CRD is reported as a conflict",
			current: newVersionedCRD("v1.5.0", crds.ChannelStandard, false),
		},
		{
			name:    "externally managed CRD without version is reported as a conflict",
			current: newVersionedCRD("", "", false),
		},
		{
			name:          "managed newer CRD is not downgraded",
			current:       newVersionedCRD("v1.7.0", crds.ChannelStandard, true),
			expectHealthy: true,
		},
		{
			name:    "managed CRD switched to experimental by the user is left alone",
			current: newVersionedCRD("v1.5.0", crds.ChannelExperimental, true),
		},
		{
			name:          "managed older CRD is upgraded",
			current:       newVersionedCRD("v1.5.0", crds.ChannelStandard, true),
			expectUpdate:  true,
			expectHealthy: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.current.Annotations["example.com/keep"] = "true"
			cs, writes := newFakeAPIExtClientset(tt.current.DeepCopy())

			err, health := installTestCRDs(t, cs, []*apiextensionsv1.CustomResourceDefinition{target.DeepCopy()})
			require.NoError(t, err, "conflicts must not fail the operator")

			crd := getCRD(t, cs, testCRDName)
			if tt.expectUpdate {
				require.Len(t, writes(), 1)
				require.Equal(t, "update", writes()[0].GetVerb())
				require.Equal(t, target.Spec, crd.Spec)
				require.Equal(t, "v1.6.1", crd.Annotations[crds.BundleVersionAnnotation])
				require.Equal(t, "true", crd.Annotations["example.com/keep"], "unrelated annotations must be retained")
			} else {
				require.Empty(t, writes())
				require.Equal(t, tt.current.Spec, crd.Spec)
				require.Equal(t, tt.current.Labels, crd.Labels)
				require.Equal(t, tt.current.Annotations, crd.Annotations)
			}

			if tt.expectHealthy {
				require.Equal(t, cell.StatusOK, health.Level)
			} else {
				require.Equal(t, cell.StatusDegraded, health.Level)
				require.Equal(t, "Gateway API CRDs conflict", health.Status)
			}
		})
	}
}

func TestInstallCRDs_UpgradeRejectedByAPIServer(t *testing.T) {
	target := newVersionedCRD("v1.6.1", crds.ChannelStandard, true)
	cs, _ := newFakeAPIExtClientset(newVersionedCRD("v1.5.0", crds.ChannelStandard, true))
	cs.PrependReactor("update", "customresourcedefinitions", func(action k8sTesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serrors.NewInvalid(schema.GroupKind{Group: "apiextensions.k8s.io", Kind: "CustomResourceDefinition"}, testCRDName,
			field.ErrorList{field.Invalid(field.NewPath("status", "storedVersions"), "v1alpha2", "must appear in spec.versions")})
	})

	err, health := installTestCRDs(t, cs, []*apiextensionsv1.CustomResourceDefinition{target})
	require.NoError(t, err)
	require.Equal(t, cell.StatusDegraded, health.Level)
	require.Equal(t, "v1.5.0", getCRD(t, cs, testCRDName).Annotations[crds.BundleVersionAnnotation])
}

func TestInstallCRDs_FailureAndRecovery(t *testing.T) {
	targets, err := bundledCRDs()
	require.NoError(t, err)
	cs, _ := newFakeAPIExtClientset()

	failing := true
	cs.PrependReactor("create", "customresourcedefinitions", func(action k8sTesting.Action) (bool, runtime.Object, error) {
		if failing {
			return true, nil, k8serrors.NewServiceUnavailable("apiserver not ready")
		}
		return false, nil, nil
	})

	err, health := installTestCRDs(t, cs, targets)
	require.Error(t, err, "transient failures must be returned so that the operator retries")
	require.Equal(t, cell.StatusDegraded, health.Level)

	// The operator restarts and retries.
	failing = false
	targets, err = bundledCRDs()
	require.NoError(t, err)
	err, health = installTestCRDs(t, cs, targets)
	require.NoError(t, err)
	require.Equal(t, cell.StatusOK, health.Level)
	for _, target := range targets {
		getCRD(t, cs, target.Name)
	}
}

func TestGatewayAPIPreconditions_InstallCRDs(t *testing.T) {
	enabled := operatorOption.Config.EnableGatewayAPI
	operatorOption.Config.EnableGatewayAPI = true
	t.Cleanup(func() { operatorOption.Config.EnableGatewayAPI = enabled })

	newParams := func(t *testing.T, installCRDs, skipCRDCreation bool) (preconditionParams, *k8sClient.FakeClientset) {
		logger := hivetest.Logger(t)
		fcs, cs := k8sClient.NewFakeClientset(logger)
		fcs.APIExtFakeClientset.PrependReactor("create", "customresourcedefinitions", func(action k8sTesting.Action) (bool, runtime.Object, error) {
			crd := action.(k8sTesting.CreateAction).GetObject().(*apiextensionsv1.CustomResourceDefinition)
			crd.Status.Conditions = append(crd.Status.Conditions, apiextensionsv1.CustomResourceDefinitionCondition{
				Type: apiextensionsv1.Established, Status: apiextensionsv1.ConditionTrue,
			})
			return false, nil, nil
		})
		health, _ := cell.NewSimpleHealth()
		return preconditionParams{
			Logger:         logger,
			K8sClient:      cs,
			Health:         health,
			OperatorConfig: &operatorOption.OperatorConfig{EnableGatewayAPI: true, KubeProxyReplacement: true},
			GatewayApiConfig: gatewayApiConfig{
				GatewayAPIServiceExternalTrafficPolicy: "Cluster",
				GatewayAPIInstallCRDs:                  installCRDs,
			},
			CRDsConfig: apis.RegisterCRDsConfig{SkipCRDCreation: skipCRDCreation},
		}, fcs
	}

	t.Run("CRDs are installed before discovery", func(t *testing.T) {
		params, fcs := newParams(t, true, false)
		result, err := newGatewayAPIPreconditions(params)
		require.NoError(t, err)
		require.True(t, result.Enabled)
		// All the optional Gateway API kinds are bundled, hence discovered.
		for _, gvk := range helpers.AllOptionalKinds {
			if gvk.Group == "gateway.networking.k8s.io" {
				require.Contains(t, result.InstalledOptionalKinds, gvk)
			}
		}
		crds, err := fcs.APIExtFakeClientset.ApiextensionsV1().CustomResourceDefinitions().List(t.Context(), metav1.ListOptions{})
		require.NoError(t, err)
		require.NotEmpty(t, crds.Items)
	})

	for _, tt := range []struct {
		name                         string
		installCRDs, skipCRDCreation bool
	}{
		{"CRD installation disabled", false, false},
		{"CRD creation skipped", true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			params, fcs := newParams(t, tt.installCRDs, tt.skipCRDCreation)
			result, err := newGatewayAPIPreconditions(params)
			require.NoError(t, err)
			require.False(t, result.Enabled, "Gateway API CRDs are missing")
			for _, a := range fcs.APIExtFakeClientset.Actions() {
				require.NotEqual(t, "create", a.GetVerb())
			}
		})
	}
}
