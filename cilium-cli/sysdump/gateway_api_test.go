// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sysdump

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
)

type discoveryClient struct {
	KubernetesClient
	resources      []*metav1.APIResourceList
	discoveryErr   error
	discoveryCalls int
	listed         []schema.GroupVersionResource
	listErr        error
}

func (c *discoveryClient) GetServerPreferredResources() ([]*metav1.APIResourceList, error) {
	c.discoveryCalls++
	return c.resources, c.discoveryErr
}

func (c *discoveryClient) ListUnstructured(_ context.Context, gvr schema.GroupVersionResource, _ *string, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	c.listed = append(c.listed, gvr)
	return &unstructured.UnstructuredList{Object: map[string]any{"apiVersion": gvr.GroupVersion().String(), "kind": "List"}}, c.listErr
}

func TestGatewayAPIVersions(t *testing.T) {
	for _, version := range []string{"v1", "v1alpha2"} {
		t.Run(version, func(t *testing.T) {
			client := &discoveryClient{resources: []*metav1.APIResourceList{
				{GroupVersion: "gateway.networking.k8s.io/" + version, APIResources: []metav1.APIResource{
					{Name: "gatewayclasses", Verbs: metav1.Verbs{"list"}},
					{Name: "gateways", Verbs: metav1.Verbs{"list"}},
					{Name: "httproutes", Verbs: metav1.Verbs{"list"}},
					{Name: "referencegrants", Verbs: metav1.Verbs{"list"}},
					{Name: "backendtlspolicies", Verbs: metav1.Verbs{"list"}},
					{Name: "listenersets", Verbs: metav1.Verbs{"list"}},
					{Name: "tcproutes", Verbs: metav1.Verbs{"list"}},
					{Name: "udproutes", Verbs: metav1.Verbs{"list"}},
					{Name: "tlsroutes", Verbs: metav1.Verbs{"list"}},
					{Name: "grpcroutes", Verbs: metav1.Verbs{"list"}},
				}},
				{GroupVersion: "cilium.io/v2alpha1", APIResources: []metav1.APIResource{
					{Name: "ciliumgatewayclassconfigs", Verbs: metav1.Verbs{"list"}},
				}},
			}}
			c := &Collector{Client: client, sysdumpDir: t.TempDir()}
			for _, task := range c.getGatewayAPITasks() {
				require.NoError(t, task.Task(context.Background()))
			}
			require.Equal(t, 1, client.discoveryCalls)
			require.Len(t, client.listed, 11)
			files, err := os.ReadDir(c.sysdumpDir)
			require.NoError(t, err)
			require.Len(t, files, 11)
			for _, file := range files {
				data, err := os.ReadFile(filepath.Join(c.sysdumpDir, file.Name()))
				require.NoError(t, err)
				require.Contains(t, string(data), "apiVersion:")
			}
			for _, gvr := range client.listed {
				if gvr.Group == "gateway.networking.k8s.io" {
					require.Equal(t, version, gvr.Version)
				} else {
					require.Equal(t, "v2alpha1", gvr.Version)
				}
			}
		})
	}
}

func TestGatewayAPIDiscoveryErrors(t *testing.T) {
	failure := errors.New("discovery unavailable")
	for _, tt := range []struct {
		name    string
		err     error
		wantErr bool
	}{
		{name: "missing resource"},
		{name: "discovery failure", err: failure, wantErr: true},
		{name: "unrelated group", err: &discovery.ErrGroupDiscoveryFailed{Groups: map[schema.GroupVersion]error{{Group: "other.example", Version: "v1"}: failure}}},
		{name: "gateway group", err: &discovery.ErrGroupDiscoveryFailed{Groups: map[schema.GroupVersion]error{{Group: "gateway.networking.k8s.io", Version: "v1"}: failure}}, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, found, err := preferredResource(tlsRoute, nil, tt.err)
			require.False(t, found)
			if tt.wantErr {
				require.ErrorIs(t, err, failure)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGatewayAPIPartialGroupDiscoveryFailure(t *testing.T) {
	failure := errors.New("discovery unavailable")
	lists := []*metav1.APIResourceList{
		{GroupVersion: "cilium.io/v2", APIResources: []metav1.APIResource{
			{Name: "ciliumnetworkpolicies", Verbs: metav1.Verbs{"list"}},
		}},
	}
	discoveryErr := &discovery.ErrGroupDiscoveryFailed{Groups: map[schema.GroupVersion]error{
		{Group: "cilium.io", Version: "v2alpha1"}: failure,
	}}
	_, found, err := preferredResource(ciliumGatewayClassConfig, lists, discoveryErr)
	require.False(t, found)
	require.ErrorIs(t, err, failure)
	require.EqualError(t, err, "cannot determine whether ciliumgatewayclassconfigs.cilium.io is installed because discovery of cilium.io/v2alpha1 failed: discovery unavailable")
}

func TestGatewayAPIListError(t *testing.T) {
	failure := errors.New("forbidden")
	client := &discoveryClient{
		resources: []*metav1.APIResourceList{{GroupVersion: "gateway.networking.k8s.io/v1", APIResources: []metav1.APIResource{{Name: "gatewayclasses", Verbs: metav1.Verbs{"list"}}}}},
		listErr:   failure,
	}
	c := &Collector{Client: client}
	for _, task := range c.getGatewayAPITasks() {
		if task.Description == "Collecting GatewayClass entries" {
			require.ErrorIs(t, task.Task(context.Background()), failure)
			return
		}
	}
	t.Fatal("GatewayClass collection task not found")
}

func TestGatewayAPIPreferredVersionPerResource(t *testing.T) {
	lists := []*metav1.APIResourceList{
		{GroupVersion: "gateway.networking.k8s.io/v1", APIResources: []metav1.APIResource{{Name: "gateways", Verbs: metav1.Verbs{"list"}}}},
		{GroupVersion: "gateway.networking.k8s.io/v1alpha2", APIResources: []metav1.APIResource{{Name: "tcproutes", Verbs: metav1.Verbs{"list"}}}},
		{GroupVersion: "gateway.networking.k8s.io/v1alpha3", APIResources: []metav1.APIResource{{Name: "backendtlspolicies", Verbs: metav1.Verbs{"list"}}}},
	}
	for _, tt := range []struct {
		resource schema.GroupResource
		version  string
	}{
		{gateway, "v1"},
		{tcpRoute, "v1alpha2"},
		{backendTLSPolicy, "v1alpha3"},
	} {
		t.Run(tt.resource.Resource, func(t *testing.T) {
			gvr, found, err := preferredResource(tt.resource, lists, nil)
			require.NoError(t, err)
			require.True(t, found)
			require.Equal(t, tt.resource.WithVersion(tt.version), gvr)
		})
	}
}

func TestGatewayAPIAbsentResources(t *testing.T) {
	client := &discoveryClient{}
	c := &Collector{Client: client, sysdumpDir: t.TempDir()}
	for _, task := range c.getGatewayAPITasks() {
		require.NoError(t, task.Task(context.Background()))
	}
	require.Equal(t, 1, client.discoveryCalls)
	require.Empty(t, client.listed)
	files, err := os.ReadDir(c.sysdumpDir)
	require.NoError(t, err)
	require.Empty(t, files)
}
