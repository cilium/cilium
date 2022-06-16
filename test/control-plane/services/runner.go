// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package services

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cilium/cilium/daemon/cmd"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/endpoint"
	fqdnproxy "github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	fakeCilium "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	fakeSlim "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"
	corev1 "k8s.io/api/core/v1"
	fakeApiExt "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

//
// Test runner for service load-balancing control-plane tests.
//
// Tests in this suite are implemented in terms of verifying
// that the control-plane correctly transforms a list of
// k8s input objects into the correct datapath (lbmap) state.
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
// - golden test with k8s objects and lbmap state expressed as
//   pretty-printed table.
//

// ValidateFunc is called on each test case step to validate the state
// of the LBMap.
type ValidateFunc func(lbmap *mockmaps.LBMockMap) error

// ServicesTestStep defines a test step, with input objects that are
// fed into the control-plane, and a validation function that is called
// after control-plane has applied the changes.
type ServicesTestStep struct {
	// Desc is the step description
	Desc string

	// Inputs is a slice of k8s objects that the control-plane should apply.
	Inputs []k8sRuntime.Object

	// Validate is called with MockLBMap after 'Inputs' are applied
	Validate ValidateFunc
}

func (t *ServicesTestStep) AddValidation(newValidate ValidateFunc) {
	oldValidate := t.Validate
	t.Validate = func(lbmap *mockmaps.LBMockMap) error {
		if err := oldValidate(lbmap); err != nil {
			return err
		}
		return newValidate(lbmap)
	}
}

func NewStep(desc string, validate ValidateFunc, inputs ...k8sRuntime.Object) *ServicesTestStep {
	return &ServicesTestStep{desc, inputs, validate}
}

// ServicesTestCase is a collection of test steps for testing the service
// load-balancing of the control-plane.
type ServicesTestCase struct {
	Steps []*ServicesTestStep
}

func NewTestCase(steps ...*ServicesTestStep) *ServicesTestCase {
	return &ServicesTestCase{steps}
}

type objectKey struct {
	gvk       schema.GroupVersionKind
	namespace string
	name      string
}

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

func (c *k8sObjectCache) updateObjects(newObjs []k8sRuntime.Object) (added, updated, deleted []k8sRuntime.Object) {
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

		_, exists := c.objs[key]
		c.objs[key] = newObj
		if exists {
			updated = append(updated, newObj)
		} else {
			added = append(added, newObj)
		}
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

// Run sets up the control-plane with a mock lbmap and executes the test case
// against it.
func (testCase *ServicesTestCase) Run(t *testing.T) {
	clients, datapath, agentHandle := startCiliumAgent()
	defer tearDown(agentHandle)
	coreTracker := clients.core.Tracker()
	slimTracker := clients.slim.Tracker()
	ciliumTracker := clients.cilium.Tracker()

	objCache := newK8sObjectCache()

	// Run through test steps and validate
	for _, step := range testCase.Steps {
		// Compute what objects got added, updated and deleted.
		// The assumption here is that each step specifies the full
		// set of objects at that point.
		// This does not include the initial set of objects given to
		// fake clients.
		//
		// TODO: add support for explicit deletes?
		added, updated, deleted := objCache.updateObjects(step.Inputs)

		for _, obj := range added {
			if coreDecoder.known(obj) {
				obj := coreDecoder.convert(obj)
				if err := coreTracker.Add(obj); err != nil {
					panic(err)
				}
			}
			if slimDecoder.known(obj) {
				obj := slimDecoder.convert(obj)
				if err := slimTracker.Add(obj); err != nil {
					panic(err)
				}
			}
			if ciliumDecoder.known(obj) {
				obj := ciliumDecoder.convert(obj)
				if err := ciliumTracker.Add(obj); err != nil {
					panic(err)
				}
			}
		}

		for _, obj := range updated {
			gvr, ns, _ := gvrAndName(obj)
			if coreDecoder.known(obj) {
				obj := coreDecoder.convert(obj)
				if err := coreTracker.Update(gvr, obj, ns); err != nil {
					panic(err)
				}
			}
			if slimDecoder.known(obj) {
				obj := slimDecoder.convert(obj)
				if err := slimTracker.Update(gvr, obj, ns); err != nil {
					panic(err)
				}
			}
			if ciliumDecoder.known(obj) {
				obj := ciliumDecoder.convert(obj)
				if err := ciliumTracker.Update(gvr, obj, ns); err != nil {
					panic(err)
				}
			}
		}

		for _, obj := range deleted {
			gvr, ns, name := gvrAndName(obj)
			if coreDecoder.known(obj) {
				if err := coreTracker.Delete(gvr, ns, name); err != nil {
					panic(err)
				}
			}
			if slimDecoder.known(obj) {
				if err := slimTracker.Delete(gvr, ns, name); err != nil {
					panic(err)
				}
			}
			if ciliumDecoder.known(obj) {
				if err := ciliumTracker.Delete(gvr, ns, name); err != nil {
					panic(err)
				}
			}
		}

		// Validate the datapath state. Since the processing of the k8s objects is asynchronous
		// and there is no obvious way to synchronize with datapath (yet), so we'll
		// try a few times and wait a bit.
		var err error
		for retries := 10; retries > 0; retries-- {
			err = step.Validate(datapath.lbmap)
			if err == nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("Test failed: %s", err)
		}
	}
}

// NewGoldenTest creates a test suite from YAML files defining
// the input events and expected LBMap output.
//
// The input events are specified in files events<N>.yaml.
// These are expected to be a k8s "List", e.g. the format of "kubectl get <res> -o yaml".
// They're fed to the control-plane in lexicographical order and after each the
// lbmap state is validated against the expected state as described by lbmap<N>.golden.
func NewGoldenTest(t *testing.T, name string, updateGolden bool) (testCase *ServicesTestCase) {
	testCase = &ServicesTestCase{}

	// Construct the test case by parsing all input event files
	// (<dir>/events*.yaml)
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
		if !strings.HasPrefix(ent.Name(), "events") || !strings.HasSuffix(ent.Name(), ".yaml") {
			continue
		}

		eventsFile := ent.Name()
		bs, err := os.ReadFile(eventsFile)
		if err != nil {
			t.Fatal(err)
		}

		// Unmarshal the input first into an unstructured list, and then
		// re-Unmarshal each object based on its "kind" using the right
		// unmarshaller.
		var items unstructured.UnstructuredList
		err = yaml.Unmarshal(bs, &items)
		if err != nil {
			t.Fatal(err)
		}
		var objs []k8sRuntime.Object
		items.EachListItem(func(obj k8sRuntime.Object) error {
			objs = append(objs, obj)
			return nil
		})

		validator := newGoldenLBMapValidator(eventsFile, updateGolden)
		testCase.Steps = append(testCase.Steps,
			NewStep(path.Join(name, path.Base(ent.Name())),
				validator.validate,
				objs...))
	}
	return
}

type dummyEpSyncher struct{}

func (epSync *dummyEpSyncher) RunK8sCiliumEndpointSync(e *endpoint.Endpoint, conf endpoint.EndpointStatusConfiguration) {
}

func (epSync *dummyEpSyncher) DeleteK8sCiliumEndpointSync(e *endpoint.Endpoint) {
}

func setupTestDirectories() {
	tempRunDir, err := os.Getwd()
	if err != nil {
		panic("TempDir() failed.")
	}
	os.Mkdir(filepath.Join(tempRunDir, "globals"), 0777)
	option.Config.RunDir = tempRunDir
	option.Config.StateDir = tempRunDir
}

// XXX hack to catch use of RESTClient() early for good stack trace
type noRESTClient struct {
	kubernetes.Interface
}

func (no noRESTClient) CoreV1() v1.CoreV1Interface {
	return noRESTClientCoreV1{no.Interface.CoreV1()}
}

type noRESTClientCoreV1 struct {
	v1.CoreV1Interface
}

func (noRESTClientCoreV1) RESTClient() rest.Interface {
	panic("NO")
}

// Kubernetes objects that we need by default to run control-plane tests.
// TODO: I just quickly generated these using kind + "kubectl get -o yaml".
// Consider generating them programmatically.
var (
	coreNode = `
apiVersion: v1
kind: Node
metadata:
  annotations:
    io.cilium.network.ipv4-cilium-host: 10.244.0.148
    io.cilium.network.ipv4-health-ip: 10.244.0.8
    io.cilium.network.ipv4-pod-cidr: 10.244.0.0/24
    kubeadm.alpha.kubernetes.io/cri-socket: unix:///run/containerd/containerd.sock
    node.alpha.kubernetes.io/ttl: "0"
    volumes.kubernetes.io/controller-managed-attach-detach: "true"
  creationTimestamp: "2022-06-16T10:06:23Z"
  labels:
    beta.kubernetes.io/arch: amd64
    beta.kubernetes.io/os: linux
    kubernetes.io/arch: amd64
    kubernetes.io/hostname: kind-control-plane
    kubernetes.io/os: linux
    node-role.kubernetes.io/control-plane: ""
    node-role.kubernetes.io/master: ""
    node.kubernetes.io/exclude-from-external-load-balancers: ""
  name: kind-control-plane
  resourceVersion: "686"
  uid: 36c24527-550b-45c9-b396-0bdcbed27a88
spec:
  podCIDR: 10.244.0.0/24
  podCIDRs:
  - 10.244.0.0/24
  providerID: kind://docker/kind/kind-control-plane
status:
  addresses:
  - address: 172.18.0.2
    type: InternalIP
  - address: kind-control-plane
    type: Hostname
  allocatable:
    cpu: "32"
    ephemeral-storage: 1912952708Ki
    hugepages-1Gi: "0"
    hugepages-2Mi: "0"
    memory: 65799872Ki
    pods: "110"
  capacity:
    cpu: "32"
    ephemeral-storage: 1912952708Ki
    hugepages-1Gi: "0"
    hugepages-2Mi: "0"
    memory: 65799872Ki
    pods: "110"
  conditions:
  daemonEndpoints:
    kubeletEndpoint:
      Port: 10250
  images:
  nodeInfo:
    architecture: amd64
    bootID: 8edfd440-545d-4da9-be72-9aed4677fd37
    containerRuntimeVersion: containerd://1.5.2
    kernelVersion: 5.15.46
    kubeProxyVersion: v1.21.1
    kubeletVersion: v1.21.1
    machineID: 36378e7b7fb9438482e218888e955c72
    operatingSystem: linux
    osImage: Ubuntu 21.04
    systemUUID: db519e4b-2628-4396-b747-593dc8b27ea3
`

	ciliumNode = `
apiVersion: cilium.io/v2
kind: CiliumNode
metadata:
  creationTimestamp: "2022-06-16T10:06:51Z"
  generation: 1
  labels:
    beta.kubernetes.io/arch: amd64
    beta.kubernetes.io/os: linux
    kubernetes.io/arch: amd64
    kubernetes.io/hostname: kind-control-plane
    kubernetes.io/os: linux
    node-role.kubernetes.io/control-plane: ""
    node-role.kubernetes.io/master: ""
    node.kubernetes.io/exclude-from-external-load-balancers: ""
  name: kind-control-plane
  ownerReferences:
  - apiVersion: v1
    kind: Node
    name: kind-control-plane
    uid: 36c24527-550b-45c9-b396-0bdcbed27a88
  resourceVersion: "598"
  uid: 3773dd5d-290b-49fe-bb24-61d3117b535b
spec:
  addresses:
  - ip: 172.18.0.2
    type: InternalIP
  - ip: 10.244.0.148
    type: CiliumInternalIP
  alibaba-cloud: {}
  azure: {}
  encryption: {}
  eni: {}
  health:
    ipv4: 10.244.0.8
  ipam:
    podCIDRs:
    - 10.244.0.0/24
`

	// endpoint_slice watcher requires at least one endpoint slice to exist, otherwise
	// it would exit.
	kubernetesEndpointSlice = `
addressType: IPv4
apiVersion: discovery.k8s.io/v1
endpoints:
- addresses:
  - 172.18.0.2
  conditions:
    ready: true
kind: EndpointSlice
metadata:
  creationTimestamp: "2022-06-16T10:06:24Z"
  generation: 1
  labels:
    kubernetes.io/service-name: kubernetes
  name: kubernetes
  namespace: default
  resourceVersion: "205"
  uid: b5880813-3d3d-432f-875d-a9934aa7b184
ports:
- name: https
  port: 6443
  protocol: TCP
`

	coreObjects = []k8sRuntime.Object{
		coreDecoder.unmarshal(coreNode),
	}

	slimCoreObjects = []k8sRuntime.Object{
		slimDecoder.unmarshal(coreNode),
		slimDecoder.unmarshal(kubernetesEndpointSlice),
	}

	ciliumObjects = []k8sRuntime.Object{
		ciliumDecoder.unmarshal(ciliumNode),
	}
)

type k8sConfig struct {
}

func (k8sConfig) K8sAPIDiscoveryEnabled() bool {
	return false
}

func (k8sConfig) K8sLeasesFallbackDiscoveryEnabled() bool {
	return false
}

type fakeClients struct {
	core   *fake.Clientset
	slim   *fakeSlim.Clientset
	cilium *fakeCilium.Clientset
	apiext *fakeApiExt.Clientset
}

type mockDatapath struct {
	lbmap *mockmaps.LBMockMap
}

type agentHandle struct {
	d *cmd.Daemon
}

func startCiliumAgent() (fakeClients, mockDatapath, agentHandle) {
	types.SetName("kind-control-plane")
	k8s.Configure("dummy", "dummy", 10.0, 10)
	version.Force("1.23")

	clients := fakeClients{
		core:   fake.NewSimpleClientset(coreObjects...),
		slim:   fakeSlim.NewSimpleClientset(slimCoreObjects...),
		cilium: fakeCilium.NewSimpleClientset(ciliumObjects...),
		apiext: fakeApiExt.NewSimpleClientset(),
	}
	k8s.SetClients(clients.core, clients.slim, clients.cilium, clients.apiext)

	proxy.DefaultDNSProxy = fqdnproxy.MockFQDNProxy{}
	option.Config.IdentityAllocationMode = option.IdentityAllocationModeCRD
	option.Config.DryMode = true
	option.Config.Opts = option.NewIntOptions(&option.DaemonMutableOptionLibrary)
	// GetConfig the default labels prefix filter
	err := labelsfilter.ParseLabelPrefixCfg(nil, "")
	if err != nil {
		panic("ParseLabelPrefixCfg() failed")
	}
	option.Config.Opts.SetBool(option.DropNotify, true)
	option.Config.Opts.SetBool(option.TraceNotify, true)
	option.Config.Opts.SetBool(option.PolicyVerdictNotify, true)
	option.Config.EnableIPSec = false
	option.Config.EnableIPv6 = false
	option.Config.KubeProxyReplacement = option.KubeProxyReplacementStrict
	option.Config.EnableHostIPRestore = false
	option.Config.K8sRequireIPv6PodCIDR = false
	option.Config.K8sEnableK8sEndpointSlice = true
	option.Config.EnableL7Proxy = false

	setupTestDirectories()

	ctx, cancel := context.WithCancel(context.Background())
	d, _, err := cmd.NewDaemon(ctx, cancel,
		cmd.WithCustomEndpointManager(&dummyEpSyncher{}),
		fakeDatapath.NewDatapath())
	if err != nil {
		panic(err)
	}
	svc := d.GetService()
	lbmap := mockmaps.NewLBMockMap()
	svc.SetLBMap(lbmap)

	go d.GetK8sWatcher().RunK8sServiceHandler()
	return clients, mockDatapath{lbmap}, agentHandle{d}
}

func tearDown(h agentHandle) {
	h.d.GetK8sWatcher().StopK8sServiceHandler()
	h.d.Close()
}

//
// Marshalling utils
//

// schemeDecoder can unmarshal from yaml and converted unstructured
// objects to structured with its scheme.
type schemeDecoder struct {
	*k8sRuntime.Scheme
}

func (d schemeDecoder) unmarshal(in string) k8sRuntime.Object {
	var obj unstructured.Unstructured
	err := yaml.Unmarshal([]byte(in), &obj)
	if err != nil {
		panic(err)
	}
	return d.convert(&obj)
}

// known returns true if the object kind is known to the scheme,
// e.g. it can decode it.
func (d schemeDecoder) known(obj k8sRuntime.Object) bool {
	gvk := obj.GetObjectKind().GroupVersionKind()
	return d.Scheme.Recognizes(gvk)
}

// convert converts the input object (usually Unstructured) using
// the scheme.
func (d schemeDecoder) convert(obj k8sRuntime.Object) k8sRuntime.Object {
	gvk := obj.GetObjectKind().GroupVersionKind()
	out, err := d.Scheme.ConvertToVersion(obj, gvk.GroupVersion())
	if err != nil {
		panic(err)
	}
	return out
}

var (
	// coreDecoder decodes objects using only the corev1 scheme
	coreDecoder = newCoreSchemeDecoder()

	// slimDecoder decodes objects with the slim scheme
	slimDecoder = newSlimSchemeDecoder()

	// ciliumDecoder decodes objects with the cilium v2 scheme
	ciliumDecoder = newCiliumSchemeDecoder()
)

func newSlimSchemeDecoder() schemeDecoder {
	s := k8sRuntime.NewScheme()
	slim_corev1.AddToScheme(s)
	slim_discovery_v1.AddToScheme(s)
	s.AddKnownTypes(slim_corev1.SchemeGroupVersion,
		&metav1.List{})
	return schemeDecoder{s}
}

func newCiliumSchemeDecoder() schemeDecoder {
	s := k8sRuntime.NewScheme()
	cilium_v2.AddToScheme(s)
	return schemeDecoder{s}
}

func newCoreSchemeDecoder() schemeDecoder {
	s := k8sRuntime.NewScheme()
	corev1.AddToScheme(s)
	return schemeDecoder{s}
}
