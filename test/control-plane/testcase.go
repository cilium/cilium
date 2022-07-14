// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package controlplane

import (
	"errors"
	"flag"
	"os"
	"path"
	"sort"
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
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"
)

//
// Test runner for control-plane tests.
//
// Tests in this suite are implemented in terms of verifying
// that the cilium control-plane correctly transforms a list of
// k8s input objects into the correct datapath state.
//
// This approach makes the test cases themselves independent
// of the internal implementation of the control-plane and
// allows using them as-is when control-plane is refactored.
//
// The test cases can be written either as:
//
// - code with manual construction of the k8s objects, steps
//   and validation functions.
//
// - golden test with k8s objects as yaml files.
//

const (
	defaultValidationTimeout = 10 * time.Second
)

// ControlPlaneTestStep defines a test step, with input objects that are
// fed into the control-plane, and a validation function that is called
// after control-plane has applied the changes.
type ControlPlaneTestStep struct {
	// Desc is the step description
	Desc string

	// Inputs is a slice of k8s objects that the control-plane should apply.
	Inputs []k8sRuntime.Object

	// Validate is called after the input objects are applied. Since the
	// changes are applied asynchronously the validation is retried multiple
	// times until it passes or timeout is reached.
	Validator Validator
}

func NewStep(desc string) *ControlPlaneTestStep {
	return &ControlPlaneTestStep{Desc: desc}
}

func (t *ControlPlaneTestStep) AddObjects(objs ...k8sRuntime.Object) *ControlPlaneTestStep {
	t.Inputs = append(t.Inputs, objs...)
	return t
}

func (t *ControlPlaneTestStep) AddValidation(newValidator Validator) *ControlPlaneTestStep {
	if t.Validator != nil {
		t.Validator = multiValidator{t.Validator, newValidator}
	} else {
		t.Validator = newValidator
	}
	return t
}

func (t *ControlPlaneTestStep) AddValidationFunc(validate func(*fakeDatapath.FakeDatapath, *K8sObjsProxy) error) *ControlPlaneTestStep {
	return t.AddValidation(funcValidator{validate})
}

type Validator interface {
	// Validate is called on each test case step to validate the state
	// of the datapath.
	Validate(datapath *fakeDatapath.FakeDatapath, proxy *K8sObjsProxy) error
}

type funcValidator struct {
	validate func(*fakeDatapath.FakeDatapath, *K8sObjsProxy) error
}

func (fv funcValidator) Validate(datapath *fakeDatapath.FakeDatapath, proxy *K8sObjsProxy) error {
	return fv.validate(datapath, proxy)
}

type multiValidator struct {
	head Validator
	tail Validator
}

func (mv multiValidator) Validate(datapath *fakeDatapath.FakeDatapath, proxy *K8sObjsProxy) error {
	if err := mv.head.Validate(datapath, proxy); err != nil {
		return err
	}
	return mv.tail.Validate(datapath, proxy)
}

// K8sObjsProxy exposes the API to access the current status
// of the mocked k8s objects during the test steps.
type K8sObjsProxy struct {
	coreTracker   k8sTesting.ObjectTracker
	slimTracker   k8sTesting.ObjectTracker
	ciliumTracker k8sTesting.ObjectTracker
}

func newK8sObjectsProxy(coreTracker, slimTracker, ciliumTracker k8sTesting.ObjectTracker) *K8sObjsProxy {
	return &K8sObjsProxy{coreTracker, slimTracker, ciliumTracker}
}

// Get retrieves a k8s object given its group-version-resource, namespace and name.
// All the mocked control plane trackers will be queried in the search:
// - core
// - slim
// - cilium
// The first match will be returned.
// If the object cannot be found, a non nil error is returned.
func (op *K8sObjsProxy) Get(gvr schema.GroupVersionResource, ns, name string) (k8sRuntime.Object, error) {
	if obj, err := op.coreTracker.Get(gvr, ns, name); err == nil {
		return obj, nil
	}
	if obj, err := op.slimTracker.Get(gvr, ns, name); err == nil {
		return obj, nil
	}
	if obj, err := op.ciliumTracker.Get(gvr, ns, name); err == nil {
		return obj, nil
	}

	return nil, errors.New("k8s object not found")
}

// ControlPlaneTestCase is a collection of test steps for testing the service
// load-balancing of the control-plane.
type ControlPlaneTestCase struct {
	NodeName          string
	InitialObjects    []k8sRuntime.Object
	Steps             []*ControlPlaneTestStep
	ValidationTimeout time.Duration
}

func toVersionInfo(rawVersion string) *version.Info {
	parts := strings.Split(rawVersion, ".")
	return &version.Info{Major: parts[0], Minor: parts[1]}
}

// Run sets up the control-plane with a mock lbmap and executes the test case
// against it.
func (testCase *ControlPlaneTestCase) Run(t *testing.T, k8sVersion string, modConfig func(*option.DaemonConfig)) {
	flag.Parse()
	if *flagDebug {
		logging.SetLogLevelToDebug()
	}
	logging.InitializeDefaultLogger()

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

	coreTracker := clients.core.Tracker()
	slimTracker := clients.slim.Tracker()
	ciliumTracker := clients.cilium.Tracker()

	// Helper to perform the action on each of the object trackers
	// that match the object's kind. The core and slim trackers overlap.
	withTracker := func(obj k8sRuntime.Object, do func(*schemeDecoder, k8sTesting.ObjectTracker)) {
		if coreDecoder.known(obj) {
			do(&coreDecoder, coreTracker)
		}
		if slimDecoder.known(obj) {
			do(&slimDecoder, slimTracker)
		}
		if ciliumDecoder.known(obj) {
			do(&ciliumDecoder, ciliumTracker)
		}
	}

	// Feed in the initial objects
	for _, obj := range testCase.InitialObjects {
		if _, ok := obj.(*unstructured.Unstructured); !ok {
			// Object is not unstructured. Convert it to one so it can be unmarshalled
			// in different ways, e.g. as v1.Node and slim_v1.Node.
			fields, err := k8sRuntime.DefaultUnstructuredConverter.ToUnstructured(obj)
			if err != nil {
				t.Fatalf("Failed to convert %T to unstructured: %s", obj, err)
			}
			obj = &unstructured.Unstructured{Object: fields}
		}

		withTracker(obj, func(decoder *schemeDecoder, tracker k8sTesting.ObjectTracker) {
			if obj, err := decoder.convert(obj); err != nil {
				t.Fatalf("Failed to convert an InitialObjects object: %s", err)
			} else {
				if err := tracker.Add(obj); err != nil {
					t.Fatalf("Failed to add object %T: %s", obj, err)
				}
			}
		})
	}

	// objCache tracks the whole set of objects that exists.
	// Each step currently needs to describe all objects that exist
	// at that point in time.
	objCache := newK8sObjectCache()

	// objProxy will be passed to the validation callbacks to expose
	// the objects status to the test case steps.
	objProxy := newK8sObjectsProxy(coreTracker, slimTracker, ciliumTracker)

	datapath, agentHandle, err := startCiliumAgent(testCase.NodeName, clients, modConfig)
	if err != nil {
		t.Fatalf("Failed to start cilium agent: %s", err)
	}
	defer agentHandle.tearDown()

	// Run through test steps and validate
	for _, step := range testCase.Steps {
		t.Run(step.Desc, func(t *testing.T) {
			updated, deleted := objCache.updateObjects(step.Inputs)

			for _, obj := range updated {
				gvr, ns, name := gvrAndName(obj)

				withTracker(obj, func(decoder *schemeDecoder, tracker k8sTesting.ObjectTracker) {
					if obj, err := decoder.convert(obj); err != nil {
						t.Fatalf("Failed to convert input object %q: %s", gvr, err)
					} else {
						if _, err := tracker.Get(gvr, ns, name); err == nil {
							if err := tracker.Update(gvr, obj, ns); err != nil {
								t.Fatalf("Failed to update object %T: %s", obj, err)
							}
						} else {
							if err := tracker.Add(obj); err != nil {
								t.Fatalf("Failed to add object %T: %s", obj, err)
							}
						}
					}
				})
			}

			for _, obj := range deleted {
				gvr, ns, name := gvrAndName(obj)
				withTracker(obj, func(decoder *schemeDecoder, tracker k8sTesting.ObjectTracker) {
					if err := tracker.Delete(gvr, ns, name); err != nil {
						t.Fatalf("Failed to delete object %T: %s", obj, err)
					}
				})
			}

			// Validate the datapath state. Since the processing of the k8s objects is asynchronous
			// and there is no obvious way to synchronize with datapath (yet), so we'll
			// try a few times and wait a bit.
			err := retryUptoDuration(
				func() error { return step.Validator.Validate(datapath, objProxy) },
				testCase.ValidationTimeout)

			// Check that the state stays correct and consistent over a short period of time
			// after the initial match.
			for retries := 3; err == nil && retries > 0; retries-- {
				time.Sleep(100 * time.Millisecond)
				err = step.Validator.Validate(datapath, objProxy)
			}
			if err != nil {
				t.Fatalf("Test failed: %s", err)
			}
		})
	}
}

// NewGoldenTest creates a test suite from YAML files defining
// the input states.
//
// The input states are specified in files state<N>.yaml.
// These are expected to be a k8s "List", e.g. the format of "kubectl get <res> -o yaml".
//
// The validation for each state is constructed with the provided 'validateState' function.
func NewGoldenTest(t *testing.T, nodeName string, validatorForState func(stateFile string, update bool) Validator) (testCase *ControlPlaneTestCase) {
	testCase = &ControlPlaneTestCase{
		NodeName:          nodeName,
		ValidationTimeout: defaultValidationTimeout,
	}

	// Get the current working directory to construct full path to input files
	// as cilium-agent will change to the run directory when it starts.
	workdir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat("init.yaml"); err == nil {
		bs, err := os.ReadFile("init.yaml")
		if err != nil {
			t.Fatalf("Failed to read init.yaml: %s", err)
		}
		testCase.InitialObjects, err = unmarshalList(bs)
		if err != nil {
			t.Fatalf("Failed to unmarshal initial objects from init.yaml: %s", err)
		}
	} else {
		t.Fatalf("%s not found. Initial objects with Node resource needed for agent to function.",
			path.Join(workdir, "init.yaml"))
	}

	// Construct the test case by parsing all input event files
	// (<dir>/state*.yaml)
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	// Sort the entries alphabetically to process the steps in the expected
	// order.
	sort.Slice(ents, func(i, j int) bool {
		return ents[i].Name() < ents[j].Name()
	})

	for _, ent := range ents {
		if !strings.HasPrefix(ent.Name(), "state") || !strings.HasSuffix(ent.Name(), ".yaml") {
			continue
		}

		stateFile := path.Join(workdir, ent.Name())
		bs, err := os.ReadFile(stateFile)
		if err != nil {
			t.Fatalf("Failed to read %q: %s", stateFile, err)
		}

		objs, err := unmarshalList(bs)
		if err != nil {
			t.Fatalf("Failed to unmarshal objects from %q: %s", stateFile, err)
		}

		testCase.Steps = append(testCase.Steps,
			&ControlPlaneTestStep{
				Desc:      ent.Name(),
				Inputs:    objs,
				Validator: validatorForState(stateFile, *flagUpdate),
			})
	}
	return
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

type objectKey struct {
	gvk       schema.GroupVersionKind
	namespace string
	name      string
}

// k8sObjectCache keeps track of objects that have been fed to the agent in order
// to distinguish between additions/updates and deletes.
type k8sObjectCache struct {
	objs map[objectKey]k8sRuntime.Object
}

func newK8sObjectCache() *k8sObjectCache {
	return &k8sObjectCache{make(map[objectKey]k8sRuntime.Object)}
}

func (c *k8sObjectCache) keys() map[objectKey]struct{} {
	keys := make(map[objectKey]struct{})
	for k := range c.objs {
		keys[k] = struct{}{}
	}
	return keys
}

type nameAndNamespace interface {
	GetName() string
	GetNamespace() string
}

func (c *k8sObjectCache) updateObjects(newObjs []k8sRuntime.Object) (updated, deleted []k8sRuntime.Object) {
	deletedKeys := c.keys()
	for _, newObj := range newObjs {

		var key objectKey
		key.gvk = newObj.GetObjectKind().GroupVersionKind()
		if acc, ok := newObj.(nameAndNamespace); !ok {
			panic("object does not implement GetName and GetNamespace")
		} else {
			key.namespace = acc.GetNamespace()
			key.name = acc.GetName()
		}

		c.objs[key] = newObj
		updated = append(updated, newObj)
		delete(deletedKeys, key)
	}

	for k := range deletedKeys {
		deleted = append(deleted, c.objs[k])
		delete(c.objs, k)
	}
	return
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
