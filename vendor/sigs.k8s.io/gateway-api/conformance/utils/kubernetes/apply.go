/*
Copyright 2022 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package kubernetes

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/gateway-api/conformance/utils/config"
)

// Applier prepares manifests depending on the available options and applies
// them to the Kubernetes cluster.
type Applier struct {
	NamespaceLabels      map[string]string
	NamespaceAnnotations map[string]string

	// GatewayClass will be used as the spec.gatewayClassName when applying Gateway resources
	GatewayClass string

	// ControllerName will be used as the spec.controllerName when applying GatewayClass resources
	ControllerName string

	// FS is the filesystem to use when reading manifests.
	FS embed.FS
}

// prepareGateway adjusts the gatewayClassName.
func (a Applier) prepareGateway(t *testing.T, uObj *unstructured.Unstructured) {
	err := unstructured.SetNestedField(uObj.Object, a.GatewayClass, "spec", "gatewayClassName")
	require.NoErrorf(t, err, "error setting `spec.gatewayClassName` on %s Gateway resource", uObj.GetName())
}

// prepareGatewayClass adjust the spec.controllerName on the resource
func (a Applier) prepareGatewayClass(t *testing.T, uObj *unstructured.Unstructured) {
	err := unstructured.SetNestedField(uObj.Object, a.ControllerName, "spec", "controllerName")
	require.NoErrorf(t, err, "error setting `spec.controllerName` on %s GatewayClass resource", uObj.GetName())
}

// prepareNamespace adjusts the Namespace labels.
func (a Applier) prepareNamespace(t *testing.T, uObj *unstructured.Unstructured) {
	labels, _, err := unstructured.NestedStringMap(uObj.Object, "metadata", "labels")
	require.NoErrorf(t, err, "error getting labels on Namespace %s", uObj.GetName())

	for k, v := range a.NamespaceLabels {
		if labels == nil {
			labels = map[string]string{}
		}

		labels[k] = v
	}

	// SetNestedStringMap converts nil to an empty map
	if labels != nil {
		err = unstructured.SetNestedStringMap(uObj.Object, labels, "metadata", "labels")
	}
	require.NoErrorf(t, err, "error setting labels on Namespace %s", uObj.GetName())

	annotations, _, err := unstructured.NestedStringMap(uObj.Object, "metadata", "annotations")
	require.NoErrorf(t, err, "error getting annotations on Namespace %s", uObj.GetName())

	for k, v := range a.NamespaceAnnotations {
		if annotations == nil {
			annotations = map[string]string{}
		}

		annotations[k] = v
	}

	// SetNestedStringMap converts nil to an empty map
	if annotations != nil {
		err = unstructured.SetNestedStringMap(uObj.Object, annotations, "metadata", "annotations")
	}
	require.NoErrorf(t, err, "error setting annotations on Namespace %s", uObj.GetName())
}

// prepareResources uses the options from an Applier to tweak resources given by
// a set of manifests.
func (a Applier) prepareResources(t *testing.T, decoder *yaml.YAMLOrJSONDecoder) ([]unstructured.Unstructured, error) {
	var resources []unstructured.Unstructured

	for {
		uObj := unstructured.Unstructured{}
		if err := decoder.Decode(&uObj); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if len(uObj.Object) == 0 {
			continue
		}

		if uObj.GetKind() == "GatewayClass" {
			a.prepareGatewayClass(t, &uObj)
		}
		if uObj.GetKind() == "Gateway" {
			a.prepareGateway(t, &uObj)
		}

		if uObj.GetKind() == "Namespace" && uObj.GetObjectKind().GroupVersionKind().Group == "" {
			a.prepareNamespace(t, &uObj)
		}

		resources = append(resources, uObj)
	}

	return resources, nil
}

func (a Applier) MustApplyObjectsWithCleanup(t *testing.T, c client.Client, timeoutConfig config.TimeoutConfig, resources []client.Object, cleanup bool) {
	for _, resource := range resources {
		resource := resource

		ctx, cancel := context.WithTimeout(context.Background(), timeoutConfig.CreateTimeout)
		defer cancel()

		t.Logf("Creating %s %s", resource.GetName(), resource.GetObjectKind().GroupVersionKind().Kind)

		err := c.Create(ctx, resource)
		if err != nil {
			if !apierrors.IsAlreadyExists(err) {
				require.NoError(t, err, "error creating resource")
			}
		}

		if cleanup {
			t.Cleanup(func() {
				ctx, cancel = context.WithTimeout(context.Background(), timeoutConfig.DeleteTimeout)
				defer cancel()
				t.Logf("Deleting %s %s", resource.GetName(), resource.GetObjectKind().GroupVersionKind().Kind)
				err = c.Delete(ctx, resource)
				require.NoErrorf(t, err, "error deleting resource")
			})
		}
	}
}

// MustApplyWithCleanup creates or updates Kubernetes resources defined with the
// provided YAML file and registers a cleanup function for resources it created.
// Note that this does not remove resources that already existed in the cluster.
func (a Applier) MustApplyWithCleanup(t *testing.T, c client.Client, timeoutConfig config.TimeoutConfig, location string, cleanup bool) {
	data, err := getContentsFromPathOrURL(a.FS, location, timeoutConfig)
	require.NoError(t, err)

	decoder := yaml.NewYAMLOrJSONDecoder(data, 4096)

	resources, err := a.prepareResources(t, decoder)
	if err != nil {
		t.Logf("manifest: %s", data.String())
		require.NoErrorf(t, err, "error parsing manifest")
	}

	for i := range resources {
		uObj := &resources[i]

		ctx, cancel := context.WithTimeout(context.Background(), timeoutConfig.CreateTimeout)
		defer cancel()

		namespacedName := types.NamespacedName{Namespace: uObj.GetNamespace(), Name: uObj.GetName()}
		fetchedObj := uObj.DeepCopy()
		err := c.Get(ctx, namespacedName, fetchedObj)
		if err != nil {
			if !apierrors.IsNotFound(err) {
				require.NoErrorf(t, err, "error getting resource")
			}
			t.Logf("Creating %s %s", uObj.GetName(), uObj.GetKind())
			err = c.Create(ctx, uObj)
			require.NoErrorf(t, err, "error creating resource")

			if cleanup {
				t.Cleanup(func() {
					ctx, cancel = context.WithTimeout(context.Background(), timeoutConfig.DeleteTimeout)
					defer cancel()
					t.Logf("Deleting %s %s", uObj.GetName(), uObj.GetKind())
					err = c.Delete(ctx, uObj)
					if !apierrors.IsNotFound(err) {
						require.NoErrorf(t, err, "error deleting resource")
					}
				})
			}
			continue
		}

		uObj.SetResourceVersion(fetchedObj.GetResourceVersion())
		t.Logf("Updating %s %s", uObj.GetName(), uObj.GetKind())
		err = c.Update(ctx, uObj)

		if cleanup {
			t.Cleanup(func() {
				ctx, cancel = context.WithTimeout(context.Background(), timeoutConfig.DeleteTimeout)
				defer cancel()
				t.Logf("Deleting %s %s", uObj.GetName(), uObj.GetKind())
				err = c.Delete(ctx, uObj)
				if !apierrors.IsNotFound(err) {
					require.NoErrorf(t, err, "error deleting resource")
				}
			})
		}
		require.NoErrorf(t, err, "error updating resource")
	}
}

// getContentsFromPathOrURL takes a string that can either be a local file
// path or an https:// URL to YAML manifests and provides the contents.
func getContentsFromPathOrURL(fs embed.FS, location string, timeoutConfig config.TimeoutConfig) (*bytes.Buffer, error) {
	if strings.HasPrefix(location, "http://") {
		return nil, fmt.Errorf("data can't be retrieved from %s: http is not supported, use https", location)
	} else if strings.HasPrefix(location, "https://") {
		ctx, cancel := context.WithTimeout(context.Background(), timeoutConfig.ManifestFetchTimeout)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
		if err != nil {
			return nil, err
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		manifests := new(bytes.Buffer)
		count, err := manifests.ReadFrom(resp.Body)
		if err != nil {
			return nil, err
		}

		if resp.ContentLength != -1 && count != resp.ContentLength {
			return nil, fmt.Errorf("received %d bytes from %s, expected %d", count, location, resp.ContentLength)
		}
		return manifests, nil
	}
	b, err := fs.ReadFile(location)
	if err != nil {
		return nil, err
	}
	return bytes.NewBuffer(b), nil
}
