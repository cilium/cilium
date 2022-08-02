// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package suite

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discov1 "k8s.io/api/discovery/v1"
	discov1beta1 "k8s.io/api/discovery/v1beta1"
	fakeApiExt "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8sTesting "k8s.io/client-go/testing"

	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	fakeCilium "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	fakeSlim "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/option"
)

const (
	validationTimeout = 10 * time.Second
)

type trackerAndDecoder struct {
	tracker k8sTesting.ObjectTracker
	decoder k8sRuntime.Decoder
}

type ControlPlaneTest struct {
	t           *testing.T
	nodeName    string
	clients     fakeClients
	trackers    []trackerAndDecoder
	agentHandle *agentHandle
	Datapath    *fakeDatapath.FakeDatapath
}

func NewControlPlaneTest(t *testing.T, nodeName string, k8sVersion string) *ControlPlaneTest {
	clients := fakeClients{
		core:   fake.NewSimpleClientset(),
		slim:   fakeSlim.NewSimpleClientset(),
		cilium: fakeCilium.NewSimpleClientset(),
		apiext: fakeApiExt.NewSimpleClientset(),
	}
	fd := clients.core.Discovery().(*fakediscovery.FakeDiscovery)
	fd.FakedServerVersion = toVersionInfo(k8sVersion)

	resources := apiResources[k8sVersion]
	clients.core.Resources = resources
	clients.slim.Resources = resources
	clients.cilium.Resources = resources
	clients.apiext.Resources = resources

	trackers := []trackerAndDecoder{
		{clients.core.Tracker(), coreDecoder},
		{clients.slim.Tracker(), slimDecoder},
		{clients.cilium.Tracker(), ciliumDecoder},
	}

	return &ControlPlaneTest{
		t:        t,
		nodeName: nodeName,
		clients:  clients,
		trackers: trackers,
	}
}

func (cpt *ControlPlaneTest) StartAgent(modConfig func(*option.DaemonConfig)) *ControlPlaneTest {
	if cpt.agentHandle != nil {
		cpt.t.Fatal("StartAgent() already called")
	}
	datapath, agentHandle, err := startCiliumAgent(cpt.nodeName, cpt.clients, modConfig)
	if err != nil {
		cpt.t.Fatalf("Failed to start cilium agent: %s", err)
	}
	cpt.agentHandle = &agentHandle
	cpt.Datapath = datapath
	return cpt
}

func (cpt *ControlPlaneTest) StopAgent() {
	cpt.agentHandle.tearDown()
	cpt.agentHandle = nil
	cpt.Datapath = nil
}

func (cpt *ControlPlaneTest) UpdateObjects(objs ...k8sRuntime.Object) *ControlPlaneTest {
	t := cpt.t
	for _, obj := range objs {
		gvr, ns, name := gvrAndName(obj)

		// Convert to unstructured form for JSON marshalling.
		// TODO: simpler way?
		uobj, ok := obj.(*unstructured.Unstructured)
		if !ok {
			fields, err := k8sRuntime.DefaultUnstructuredConverter.ToUnstructured(obj)
			if err != nil {
				t.Fatalf("Failed to convert %T to unstructured: %s", obj, err)
			}
			uobj = &unstructured.Unstructured{Object: fields}
		}

		// Marshal the object to JSON in order to allow decoding it in different ways,
		// e.g. as v1.Node and as slim_corev1.Node. This avoids having to write both
		// the core and slim versions of the object in the test case.
		jsonBytes, err := uobj.MarshalJSON()
		if err != nil {
			t.Fatalf("Failed to marshal %T to JSON: %s", obj, err)
		}

		accepted := false
		var errors []error
		for _, td := range cpt.trackers {
			if obj, _, err := td.decoder.Decode(jsonBytes, nil, nil); err == nil {
				accepted = true

				if _, err := td.tracker.Get(gvr, ns, name); err == nil {
					if err := td.tracker.Update(gvr, obj, ns); err != nil {
						t.Fatalf("Failed to update object %T: %s", obj, err)
					}
				} else {
					if err := td.tracker.Add(obj); err != nil {
						t.Fatalf("Failed to add object %T: %s", obj, err)
					}
				}
			} else {
				errors = append(errors, err)
			}
		}
		if !accepted {
			t.Fatalf("None of the decoders accepted %s: %v", gvr, errors)
		}
	}
	return cpt
}

// Get retrieves a k8s object given its group-version-resource, namespace and name.
// All the mocked control plane trackers will be queried in the search:
// - core
// - slim
// - cilium
// The first match will be returned.
// If the object cannot be found, a non nil error is returned.
func (cpt *ControlPlaneTest) Get(gvr schema.GroupVersionResource, ns, name string) (k8sRuntime.Object, error) {
	for _, td := range cpt.trackers {
		if obj, err := td.tracker.Get(gvr, ns, name); err == nil {
			return obj, nil
		}
	}
	return nil, errors.New("k8s object not found")
}

func (cpt *ControlPlaneTest) UpdateObjectsFromFile(filename string) *ControlPlaneTest {
	bs, err := os.ReadFile(filename)
	if err != nil {
		cpt.t.Fatalf("Failed to read %s: %s", filename, err)
	}
	objs, err := unmarshalList(bs)
	if err != nil {
		cpt.t.Fatalf("Failed to unmarshal objects from %s: %s", filename, err)
	}
	return cpt.UpdateObjects(objs...)
}

func (cpt *ControlPlaneTest) DeleteObjects(objs ...k8sRuntime.Object) *ControlPlaneTest {
	for _, obj := range objs {
		gvr, ns, name := gvrAndName(obj)

		deleted := false
		for _, td := range cpt.trackers {
			if err := td.tracker.Delete(gvr, ns, name); err == nil {
				deleted = true
			}
		}
		if !deleted {
			cpt.t.Fatalf("Failed to delete object %s/%s as it was not found", ns, name)
		}
	}
	return cpt
}

func (cpt *ControlPlaneTest) Eventually(check func() error) *ControlPlaneTest {
	if err := retryUptoDuration(check, validationTimeout); err != nil {
		cpt.t.Fatal(err)
	}
	return cpt
}

func retryUptoDuration(act func() error, maxDuration time.Duration) error {
	wait := 50 * time.Millisecond
	end := time.Now().Add(maxDuration)

	for time.Now().Add(wait).Before(end) {
		time.Sleep(wait)
		if err := act(); err == nil {
			return nil
		}
		wait *= 2
	}

	time.Sleep(end.Sub(time.Now()))
	return act()
}

func toVersionInfo(rawVersion string) *version.Info {
	parts := strings.Split(rawVersion, ".")
	return &version.Info{Major: parts[0], Minor: parts[1]}
}

func gvrAndName(obj k8sRuntime.Object) (gvr schema.GroupVersionResource, ns string, name string) {
	gvk := obj.GetObjectKind().GroupVersionKind()
	gvr, _ = meta.UnsafeGuessKindToResource(gvk)
	objMeta, err := meta.Accessor(obj)
	if err != nil {
		panic(err)
	}
	ns = objMeta.GetNamespace()
	name = objMeta.GetName()
	return
}

var (
	corev1APIResources = &metav1.APIResourceList{
		GroupVersion: corev1.SchemeGroupVersion.String(),
		APIResources: []metav1.APIResource{
			{Name: "nodes", Kind: "Node"},
			{Name: "pods", Namespaced: true, Kind: "Pod"},
			{Name: "services", Namespaced: true, Kind: "Service"},
			{Name: "endpoints", Namespaced: true, Kind: "Endpoint"},
		},
	}

	ciliumv2APIResources = &metav1.APIResourceList{
		TypeMeta:     metav1.TypeMeta{},
		GroupVersion: cilium_v2.SchemeGroupVersion.String(),
		APIResources: []metav1.APIResource{
			{Name: cilium_v2.CNPluralName, Kind: cilium_v2.CNKindDefinition},
			{Name: cilium_v2.CEPPluralName, Namespaced: true, Kind: cilium_v2.CEPKindDefinition},
			{Name: cilium_v2.CIDPluralName, Namespaced: true, Kind: cilium_v2.CIDKindDefinition},
			{Name: cilium_v2.CEGPPluralName, Namespaced: true, Kind: cilium_v2.CEGPKindDefinition},
			{Name: cilium_v2.CNPPluralName, Namespaced: true, Kind: cilium_v2.CNPKindDefinition},
			{Name: cilium_v2.CCNPPluralName, Namespaced: true, Kind: cilium_v2.CCNPKindDefinition},
			{Name: cilium_v2.CLRPPluralName, Namespaced: true, Kind: cilium_v2.CLRPKindDefinition},
			{Name: cilium_v2.CEWPluralName, Namespaced: true, Kind: cilium_v2.CEWKindDefinition},
			{Name: cilium_v2.CCECPluralName, Namespaced: true, Kind: cilium_v2.CCECKindDefinition},
			{Name: cilium_v2.CECPluralName, Namespaced: true, Kind: cilium_v2.CECKindDefinition},
		},
	}

	discoveryV1APIResources = &metav1.APIResourceList{
		TypeMeta:     metav1.TypeMeta{},
		GroupVersion: discov1.SchemeGroupVersion.String(),
		APIResources: []metav1.APIResource{
			{Name: "endpointslices", Namespaced: true, Kind: "EndpointSlice"},
		},
	}

	discoveryV1beta1APIResources = &metav1.APIResourceList{
		GroupVersion: discov1beta1.SchemeGroupVersion.String(),
		APIResources: []metav1.APIResource{
			{Name: "endpointslices", Namespaced: true, Kind: "EndpointSlice"},
		},
	}

	// apiResources is the list of API resources for the k8s version that we're mocking.
	// This is mostly relevant for the feature detection at pkg/k8s/version/version.go.
	// The lists here are currently not exhaustive and expanded on need-by-need basis.
	apiResources = map[string][]*metav1.APIResourceList{
		"1.20": {
			corev1APIResources,
			discoveryV1beta1APIResources,
			ciliumv2APIResources,
		},
		"1.21": {
			corev1APIResources,
			discoveryV1APIResources,
			discoveryV1beta1APIResources,
			ciliumv2APIResources,
		},
		"1.22": {
			corev1APIResources,
			discoveryV1APIResources,
			discoveryV1beta1APIResources,
			ciliumv2APIResources,
		},
		"1.23": {
			corev1APIResources,
			discoveryV1APIResources,
			discoveryV1beta1APIResources,
			ciliumv2APIResources,
		},
		"1.24": {
			corev1APIResources,
			discoveryV1APIResources,
			discoveryV1beta1APIResources,
			ciliumv2APIResources,
		},
	}
)
