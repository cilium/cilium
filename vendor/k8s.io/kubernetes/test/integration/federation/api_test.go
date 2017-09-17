/*
Copyright 2015 The Kubernetes Authors.

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

package federation

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	autoscaling_v1 "k8s.io/api/autoscaling/v1"
	batch_v1 "k8s.io/api/batch/v1"
	"k8s.io/api/core/v1"
	ext_v1b1 "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fed_v1b1 "k8s.io/kubernetes/federation/apis/federation/v1beta1"
	"k8s.io/kubernetes/test/integration/federation/framework"
)

// List of group versions that are enabled by default.
var enabledGroupVersions = []schema.GroupVersion{
	fed_v1b1.SchemeGroupVersion,
	ext_v1b1.SchemeGroupVersion,
}

// List of group versions that are disabled by default.
var disabledGroupVersions = []schema.GroupVersion{
	batch_v1.SchemeGroupVersion,
	autoscaling_v1.SchemeGroupVersion,
}

type apiTestFunc func(t *testing.T, host string, expectedGroupVersions []schema.GroupVersion)

func testFederationAPI(t *testing.T, runtimeConfig string, expectedGroupVersions []schema.GroupVersion) {
	f := &framework.FederationAPIFixture{}
	if runtimeConfig == "" {
		f.SetUp(t)
	} else {
		runOptions := framework.GetRunOptions()
		runOptions.APIEnablement.RuntimeConfig.Set(runtimeConfig)
		f.SetUpWithRunOptions(t, runOptions)
	}
	defer f.TearDown(t)

	testCases := map[string]apiTestFunc{
		"swaggerSpec":     testSwaggerSpec,
		"support":         testSupport,
		"apiGroupList":    testAPIGroupList,
		"apiGroup":        testAPIGroup,
		"apiResourceList": testAPIResourceList,
	}
	for testName, testFunc := range testCases {
		t.Run(testName, func(t *testing.T) {
			testFunc(t, f.Host, expectedGroupVersions)
		})
	}
}

// Verifies that only default APIs are enabled when no runtime config is set.
func TestDefaultRun(t *testing.T) {
	testFederationAPI(t, "", enabledGroupVersions)
}

// Verifies that all APIs are enabled when runtime config is set to all.
func TestRunWithRuntimeConfigAll(t *testing.T) {
	expectedGroupVersions := enabledGroupVersions
	expectedGroupVersions = append(enabledGroupVersions, disabledGroupVersions...)
	testFederationAPI(t, "api/all=true", expectedGroupVersions)
}

func readResponse(serverURL string) ([]byte, error) {
	response, err := http.Get(serverURL)
	if err != nil {
		return nil, fmt.Errorf("Error in fetching %s: %v", serverURL, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d for URL: %s, expected status: %d", response.StatusCode, serverURL, http.StatusOK)
	}
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading response from %s: %v", serverURL, err)
	}
	return contents, nil
}

func testSwaggerSpec(t *testing.T, host string, expectedGroupVersions []schema.GroupVersion) {
	serverURL := host + "/swaggerapi"
	_, err := readResponse(serverURL)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func testSupport(t *testing.T, host string, expectedGroupVersions []schema.GroupVersion) {
	serverURL := host + "/version"
	_, err := readResponse(serverURL)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func findGroup(groups []metav1.APIGroup, groupName string) *metav1.APIGroup {
	for _, group := range groups {
		if group.Name == groupName {
			return &group
		}
	}
	return nil
}

func testAPIGroupList(t *testing.T, host string, expectedGroupVersions []schema.GroupVersion) {
	groupVersionForDiscoveryMap := make(map[string]metav1.GroupVersionForDiscovery)
	for _, groupVersion := range expectedGroupVersions {
		groupVersionForDiscoveryMap[groupVersion.Group] = metav1.GroupVersionForDiscovery{
			GroupVersion: groupVersion.String(),
			Version:      groupVersion.Version,
		}
	}

	serverURL := host + "/apis"
	contents, err := readResponse(serverURL)
	if err != nil {
		t.Fatalf("%v", err)
	}
	var apiGroupList metav1.APIGroupList
	err = json.Unmarshal(contents, &apiGroupList)
	if err != nil {
		t.Fatalf("Error in unmarshalling response from server %s: %v", serverURL, err)
	}

	assert.Equal(t, len(apiGroupList.Groups), len(expectedGroupVersions), "expected: %v, actual: %v", expectedGroupVersions, apiGroupList.Groups)
	for _, groupVersion := range expectedGroupVersions {
		found := findGroup(apiGroupList.Groups, groupVersion.Group)
		assert.NotNil(t, found)
		assert.Equal(t, groupVersion.Group, found.Name)
		assert.Equal(t, 1, len(found.Versions))
		groupVersionForDiscovery := groupVersionForDiscoveryMap[groupVersion.Group]
		assert.Equal(t, groupVersionForDiscovery, found.Versions[0])
		assert.Equal(t, groupVersionForDiscovery, found.PreferredVersion)
	}
}

func testAPIGroup(t *testing.T, host string, expectedGroupVersions []schema.GroupVersion) {
	for _, groupVersion := range expectedGroupVersions {
		serverURL := host + "/apis/" + groupVersion.Group
		contents, err := readResponse(serverURL)
		if err != nil {
			t.Fatalf("%v", err)
		}
		var apiGroup metav1.APIGroup
		err = json.Unmarshal(contents, &apiGroup)
		if err != nil {
			t.Fatalf("Error in unmarshalling response from server %s: %v", serverURL, err)
		}
		// empty APIVersion for extensions group
		if groupVersion.Group == "extensions" {
			assert.Equal(t, "", apiGroup.APIVersion)
		} else {
			assert.Equal(t, "v1", apiGroup.APIVersion)
		}
		assert.Equal(t, apiGroup.Name, groupVersion.Group)
		assert.Equal(t, 1, len(apiGroup.Versions))
		assert.Equal(t, groupVersion.String(), apiGroup.Versions[0].GroupVersion)
		assert.Equal(t, groupVersion.Version, apiGroup.Versions[0].Version)
		assert.Equal(t, apiGroup.PreferredVersion, apiGroup.Versions[0])
	}

	testCoreAPIGroup(t, host)
}

func testCoreAPIGroup(t *testing.T, host string) {
	serverURL := host + "/api"
	contents, err := readResponse(serverURL)
	if err != nil {
		t.Fatalf("%v", err)
	}
	var apiVersions metav1.APIVersions
	err = json.Unmarshal(contents, &apiVersions)
	if err != nil {
		t.Fatalf("Error in unmarshalling response from server %s: %v", serverURL, err)
	}
	assert.Equal(t, 1, len(apiVersions.Versions))
	assert.Equal(t, "v1", apiVersions.Versions[0])
	assert.NotEmpty(t, apiVersions.ServerAddressByClientCIDRs)
}

func findResource(resources []metav1.APIResource, resourceName string) *metav1.APIResource {
	for _, resource := range resources {
		if resource.Name == resourceName {
			return &resource
		}
	}
	return nil
}

func testAPIResourceList(t *testing.T, host string, expectedGroupVersions []schema.GroupVersion) {
	testFederationResourceList(t, host)
	testCoreResourceList(t, host)
	testExtensionsResourceList(t, host)
	if contains(expectedGroupVersions, batch_v1.SchemeGroupVersion) {
		testBatchResourceList(t, host)
	}
	if contains(expectedGroupVersions, autoscaling_v1.SchemeGroupVersion) {
		testAutoscalingResourceList(t, host)
	}
}

func contains(gvs []schema.GroupVersion, requiredGV schema.GroupVersion) bool {
	for _, gv := range gvs {
		if gv.String() == requiredGV.String() {
			return true
		}
	}
	return false
}

func testFederationResourceList(t *testing.T, host string) {
	serverURL := host + "/apis/" + fed_v1b1.SchemeGroupVersion.String()
	contents, err := readResponse(serverURL)
	if err != nil {
		t.Fatalf("%v", err)
	}
	var apiResourceList metav1.APIResourceList
	err = json.Unmarshal(contents, &apiResourceList)
	if err != nil {
		t.Fatalf("Error in unmarshalling response from server %s: %v", serverURL, err)
	}
	assert.Equal(t, "v1", apiResourceList.APIVersion)
	assert.Equal(t, fed_v1b1.SchemeGroupVersion.String(), apiResourceList.GroupVersion)
	// Assert that there are exactly 2 resources.
	assert.Equal(t, 2, len(apiResourceList.APIResources))

	found := findResource(apiResourceList.APIResources, "clusters")
	assert.NotNil(t, found)
	assert.False(t, found.Namespaced)
	found = findResource(apiResourceList.APIResources, "clusters/status")
	assert.NotNil(t, found)
	assert.False(t, found.Namespaced)
}

func testCoreResourceList(t *testing.T, host string) {
	serverURL := host + "/api/" + v1.SchemeGroupVersion.String()
	contents, err := readResponse(serverURL)
	if err != nil {
		t.Fatalf("%v", err)
	}
	var apiResourceList metav1.APIResourceList
	err = json.Unmarshal(contents, &apiResourceList)
	if err != nil {
		t.Fatalf("Error in unmarshalling response from server %s: %v", serverURL, err)
	}
	assert.Equal(t, "", apiResourceList.APIVersion)
	assert.Equal(t, v1.SchemeGroupVersion.String(), apiResourceList.GroupVersion)
	assert.Equal(t, 8, len(apiResourceList.APIResources), "ResourceList: %v", apiResourceList.APIResources)

	// Verify services.
	found := findResource(apiResourceList.APIResources, "services")
	assert.NotNil(t, found)
	assert.True(t, found.Namespaced)
	found = findResource(apiResourceList.APIResources, "services/status")
	assert.NotNil(t, found)
	assert.True(t, found.Namespaced)

	// Verify namespaces.
	found = findResource(apiResourceList.APIResources, "namespaces")
	assert.NotNil(t, found)
	assert.False(t, found.Namespaced)
	found = findResource(apiResourceList.APIResources, "namespaces/status")
	assert.NotNil(t, found)
	assert.False(t, found.Namespaced)
	found = findResource(apiResourceList.APIResources, "namespaces/finalize")
	assert.NotNil(t, found)
	assert.False(t, found.Namespaced)

	// Verify events.
	found = findResource(apiResourceList.APIResources, "events")
	assert.NotNil(t, found)
	assert.True(t, found.Namespaced)

	// Verify secrets.
	found = findResource(apiResourceList.APIResources, "secrets")
	assert.NotNil(t, found)
	assert.True(t, found.Namespaced)

	// Verify config maps.
	found = findResource(apiResourceList.APIResources, "configmaps")
	assert.NotNil(t, found)
	assert.True(t, found.Namespaced)
}

func testExtensionsResourceList(t *testing.T, host string) {
	serverURL := host + "/apis/" + ext_v1b1.SchemeGroupVersion.String()
	contents, err := readResponse(serverURL)
	if err != nil {
		t.Fatalf("%v", err)
	}
	var apiResourceList metav1.APIResourceList
	err = json.Unmarshal(contents, &apiResourceList)
	if err != nil {
		t.Fatalf("Error in unmarshalling response from server %s: %v", serverURL, err)
	}
	// empty APIVersion for extensions group
	assert.Equal(t, "", apiResourceList.APIVersion)
	assert.Equal(t, ext_v1b1.SchemeGroupVersion.String(), apiResourceList.GroupVersion)
	// Assert that there are exactly 11 resources.
	assert.Equal(t, 11, len(apiResourceList.APIResources))

	// Verify replicasets.
	found := findResource(apiResourceList.APIResources, "replicasets")
	assert.NotNil(t, found)
	assert.True(t, found.Namespaced)
	found = findResource(apiResourceList.APIResources, "replicasets/status")
	assert.NotNil(t, found)
	assert.True(t, found.Namespaced)
	found = findResource(apiResourceList.APIResources, "replicasets/scale")
	assert.NotNil(t, found)
	assert.True(t, found.Namespaced)

	// Verify ingress.
	found = findResource(apiResourceList.APIResources, "ingresses")
	assert.NotNil(t, found)
	assert.True(t, found.Namespaced)
	found = findResource(apiResourceList.APIResources, "ingresses/status")
	assert.NotNil(t, found)
	assert.True(t, found.Namespaced)

	// Verify daemonsets.
	found = findResource(apiResourceList.APIResources, "daemonsets")
	assert.NotNil(t, found)
	assert.True(t, found.Namespaced)
	found = findResource(apiResourceList.APIResources, "daemonsets/status")
	assert.NotNil(t, found)
	assert.True(t, found.Namespaced)

	// Verify deployments.
	found = findResource(apiResourceList.APIResources, "deployments")
	assert.NotNil(t, found)
	assert.True(t, found.Namespaced)
	found = findResource(apiResourceList.APIResources, "deployments/status")
	assert.NotNil(t, found)
	assert.True(t, found.Namespaced)
	found = findResource(apiResourceList.APIResources, "deployments/scale")
	assert.NotNil(t, found)
	assert.True(t, found.Namespaced)
	found = findResource(apiResourceList.APIResources, "deployments/rollback")
}

func testBatchResourceList(t *testing.T, host string) {
	serverURL := host + "/apis/" + batch_v1.SchemeGroupVersion.String()
	contents, err := readResponse(serverURL)
	if err != nil {
		t.Fatalf("%v", err)
	}
	var apiResourceList metav1.APIResourceList
	err = json.Unmarshal(contents, &apiResourceList)
	if err != nil {
		t.Fatalf("Error in unmarshalling response from server %s: %v", serverURL, err)
	}
	// empty APIVersion for extensions group
	assert.Equal(t, "v1", apiResourceList.APIVersion)
	assert.Equal(t, batch_v1.SchemeGroupVersion.String(), apiResourceList.GroupVersion)
	// Assert that there are exactly this number of resources.
	assert.Equal(t, 2, len(apiResourceList.APIResources))

	// Verify jobs
	found := findResource(apiResourceList.APIResources, "jobs")
	assert.NotNil(t, found)
	assert.True(t, found.Namespaced)
	found = findResource(apiResourceList.APIResources, "jobs/status")
	assert.NotNil(t, found)
	assert.True(t, found.Namespaced)
}

func testAutoscalingResourceList(t *testing.T, host string) {
	serverURL := host + "/apis/" + autoscaling_v1.SchemeGroupVersion.String()
	contents, err := readResponse(serverURL)
	if err != nil {
		t.Fatalf("%v", err)
	}
	var apiResourceList metav1.APIResourceList
	err = json.Unmarshal(contents, &apiResourceList)
	if err != nil {
		t.Fatalf("Error in unmarshalling response from server %s: %v", serverURL, err)
	}
	// empty APIVersion for extensions group
	assert.Equal(t, "v1", apiResourceList.APIVersion)
	assert.Equal(t, autoscaling_v1.SchemeGroupVersion.String(), apiResourceList.GroupVersion)
	// Assert that there are exactly this number of resources.
	assert.Equal(t, 2, len(apiResourceList.APIResources))

	// Verify hpa
	found := findResource(apiResourceList.APIResources, "horizontalpodautoscalers")
	assert.NotNil(t, found)
	assert.True(t, found.Namespaced)
	found = findResource(apiResourceList.APIResources, "horizontalpodautoscalers/status")
	assert.NotNil(t, found)
	assert.True(t, found.Namespaced)
}
