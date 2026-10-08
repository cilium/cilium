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
	"text/template"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/network-policy-api/conformance/utils/config"
)

// Applier prepares manifests depending on the available options and applies
// them to the Kubernetes cluster.
type Applier struct {
	NamespaceLabels  map[string]string
	HostNetworkPorts []int

	// FS is the filesystem to use when reading manifests.
	FS embed.FS
}

// TemplateData structure passed to the template to generate dynamic manifests.
type TemplateData struct {
	HostNetworkPorts []int
}

// prepareNamespace adjusts the Namespace labels.
func prepareNamespace(t *testing.T, uObj *unstructured.Unstructured, namespaceLabels map[string]string) {
	labels, _, err := unstructured.NestedStringMap(uObj.Object, "metadata", "labels")
	require.NoErrorf(t, err, "error getting labels on Namespace %s", uObj.GetName())

	for k, v := range namespaceLabels {
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
}

func applyTemplate(t *testing.T, file string, hostNetworkPorts []int) *bytes.Buffer {
	data := TemplateData{HostNetworkPorts: hostNetworkPorts}

	tmpl, err := template.New("tmp").Parse(file)
	require.NoErrorf(t, err, "error parsing template %v", err)

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, data)
	require.NoErrorf(t, err, "error executing template: %v", err)

	return &buf
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

		if uObj.GetKind() == "Namespace" && uObj.GetObjectKind().GroupVersionKind().Group == "" {
			prepareNamespace(t, &uObj, a.NamespaceLabels)
		}

		resources = append(resources, uObj)
	}

	return resources, nil
}

// MustApplyWithCleanup creates or updates Kubernetes resources defined with the
// provided YAML file and registers a cleanup function for resources it created.
// Note that this does not remove resources that already existed in the cluster.
func (a Applier) MustApplyWithCleanup(t *testing.T, c client.Client, timeoutConfig config.TimeoutConfig, location string, cleanup bool) {
	data, err := getContentsFromPathOrURL(a.FS, location, timeoutConfig)
	require.NoError(t, err)

	// apply template to manifests first to insert dynamic values
	newData := applyTemplate(t, data.String(), a.HostNetworkPorts)
	decoder := yaml.NewYAMLOrJSONDecoder(newData, 4096)

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
