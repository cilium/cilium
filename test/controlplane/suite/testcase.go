// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package suite

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	discov1 "k8s.io/api/discovery/v1"
	discov1beta1 "k8s.io/api/discovery/v1beta1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	versionapi "k8s.io/apimachinery/pkg/version"
	"k8s.io/apimachinery/pkg/watch"
	fakediscovery "k8s.io/client-go/discovery/fake"
	k8sTesting "k8s.io/client-go/testing"

	agentCmd "github.com/cilium/cilium/daemon/cmd"
	operatorCmd "github.com/cilium/cilium/operator/cmd"
	operatorOption "github.com/cilium/cilium/operator/option"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	fqdnproxy "github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s/apis"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/node/types"
	agentOption "github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy"
)

const (
	validationTimeout = 10 * time.Second
)

type trackerAndDecoder struct {
	tracker k8sTesting.ObjectTracker
	decoder k8sRuntime.Decoder
}

type ControlPlaneTest struct {
	t              *testing.T
	nodeName       string
	clients        *k8sClient.FakeClientset
	trackers       []trackerAndDecoder
	agentHandle    *agentHandle
	operatorHandle *operatorHandle
	Datapath       *fakeDatapath.FakeDatapath
}

func NewControlPlaneTest(t *testing.T, nodeName string, k8sVersion string) *ControlPlaneTest {
	clients, _ := k8sClient.NewFakeClientset()
	clients.KubernetesFakeClientset = addFieldSelection(clients.KubernetesFakeClientset)
	clients.SlimFakeClientset = addFieldSelection(clients.SlimFakeClientset)
	clients.CiliumFakeClientset = addFieldSelection(clients.CiliumFakeClientset)
	clients.APIExtFakeClientset = addFieldSelection(clients.APIExtFakeClientset)
	fd := clients.KubernetesFakeClientset.Discovery().(*fakediscovery.FakeDiscovery)
	fd.FakedServerVersion = toVersionInfo(k8sVersion)

	resources, ok := apiResources[k8sVersion]
	if !ok {
		panic(fmt.Sprintf("k8s version %s not found in apiResources", k8sVersion))
	}
	clients.KubernetesFakeClientset.Resources = resources
	clients.SlimFakeClientset.Resources = resources
	clients.CiliumFakeClientset.Resources = resources
	clients.APIExtFakeClientset.Resources = resources

	trackers := []trackerAndDecoder{
		{clients.KubernetesFakeClientset.Tracker(), coreDecoder},
		{clients.SlimFakeClientset.Tracker(), slimDecoder},
		{clients.CiliumFakeClientset.Tracker(), ciliumDecoder},
	}

	return &ControlPlaneTest{
		t:        t,
		nodeName: nodeName,
		clients:  clients,
		trackers: trackers,
	}
}

// SetupEnvironment sets the fake k8s clients and the mock FQDN proxy required for control-plane testing.
// Then, it loads the defaults values for both the daemon and the operator configurations.
// Finally, it calls modConfig to overwrite testcase specific global options values.
func (cpt *ControlPlaneTest) SetupEnvironment(modConfig func(*agentOption.DaemonConfig, *operatorOption.OperatorConfig)) *ControlPlaneTest {
	types.SetName(cpt.nodeName)

	// Configure k8s and perform capability detection with the fake client.
	version.Update(cpt.clients, true)

	agentOption.Config.Populate(agentCmd.Vp)
	agentOption.Config.IdentityAllocationMode = agentOption.IdentityAllocationModeCRD
	agentOption.Config.DryMode = true
	agentOption.Config.IPAM = ipamOption.IPAMKubernetes
	agentOption.Config.Opts = agentOption.NewIntOptions(&agentOption.DaemonMutableOptionLibrary)
	agentOption.Config.Opts.SetBool(agentOption.DropNotify, true)
	agentOption.Config.Opts.SetBool(agentOption.TraceNotify, true)
	agentOption.Config.Opts.SetBool(agentOption.PolicyVerdictNotify, true)
	agentOption.Config.Opts.SetBool(agentOption.Debug, true)
	agentOption.Config.EnableIPSec = false
	agentOption.Config.EnableIPv6 = false
	agentOption.Config.KubeProxyReplacement = agentOption.KubeProxyReplacementStrict
	agentOption.Config.EnableHostIPRestore = false
	agentOption.Config.K8sRequireIPv6PodCIDR = false
	agentOption.Config.K8sEnableK8sEndpointSlice = true
	agentOption.Config.EnableL7Proxy = false
	agentOption.Config.EnableHealthCheckNodePort = false
	agentOption.Config.Debug = true

	operatorOption.Config.Populate(operatorCmd.Vp)

	// Apply the test specific global configuration
	modConfig(agentOption.Config, operatorOption.Config)

	if agentOption.Config.EnableL7Proxy {
		proxy.DefaultDNSProxy = fqdnproxy.MockFQDNProxy{}
	}
	return cpt
}

func (cpt *ControlPlaneTest) StartAgent() *ControlPlaneTest {
	if cpt.agentHandle != nil {
		cpt.t.Fatal("StartAgent() already called")
	}
	datapath, agentHandle, err := startCiliumAgent(cpt.t, cpt.clients)
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

func (cpt *ControlPlaneTest) StartOperator(modCellConfig func(vp *viper.Viper)) *ControlPlaneTest {
	if cpt.operatorHandle != nil {
		cpt.t.Fatal("StartOperator() already called")
	}

	cpt.operatorHandle = &operatorHandle{
		t: cpt.t,
		hive: hive.New(
			cell.Provide(func() k8sClient.Clientset {
				return cpt.clients
			}),
			operatorCmd.OperatorCell,
		),
	}

	cpt.operatorHandle.hive.Viper().Set(apis.SkipCRDCreation, true)

	// Apply the test specific cells configuration
	//
	// Unlike global configuration options, cell-specific configuration options
	// (i.e. the ones defined through cell.Config(...)) will not be loaded from
	// agentOption or operatorOption, but from the *viper.Viper object bound to
	// the test hive.
	// modCellConfig function exposes the operator hive viper struct to each
	// controlplane test, so to allow changing those options as needed.
	modCellConfig(cpt.operatorHandle.hive.Viper())

	// Disable support for operator HA. This should be cleaned up
	// by injecting the capabilities, or by supporting the leader
	// election machinery in the controlplane tests.
	version.DisableLeasesResourceLock()

	err := cpt.operatorHandle.hive.Start(context.Background())
	if err != nil {
		cpt.t.Fatalf("Failed to start operator: %s", err)
	}

	return cpt
}

func (cpt *ControlPlaneTest) StopOperator() {
	cpt.operatorHandle.tearDown()
	cpt.operatorHandle = nil
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
	var (
		obj k8sRuntime.Object
		err error
	)
	for _, td := range cpt.trackers {
		if obj, err = td.tracker.Get(gvr, ns, name); err == nil {
			return obj, nil
		}
	}
	return nil, err
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

func (cpt *ControlPlaneTest) Execute(task func() error) *ControlPlaneTest {
	if err := task(); err != nil {
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

func toVersionInfo(rawVersion string) *versionapi.Info {
	parts := strings.Split(rawVersion, ".")
	return &versionapi.Info{Major: parts[0], Minor: parts[1]}
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
		"1.24": {
			corev1APIResources,
			discoveryV1APIResources,
			discoveryV1beta1APIResources,
			ciliumv2APIResources,
		},
		"1.25": {
			corev1APIResources,
			discoveryV1APIResources,
			ciliumv2APIResources,
		},
		"1.26": {
			corev1APIResources,
			discoveryV1APIResources,
			ciliumv2APIResources,
		},
	}
)

func matchFieldSelector(obj k8sRuntime.Object, selector fields.Selector) bool {
	if selector == nil {
		return true
	}

	fs := fields.Set{}
	acc, err := meta.Accessor(obj)
	if err != nil {
		panic(err)
	}
	fs["metadata.name"] = acc.GetName()
	fs["metadata.namespace"] = acc.GetNamespace()

	// Special handling for specific objects. Only add things here that k8s api-server
	// handles, see for example ToSelectableFields() in pkg/registry/core/pod/strategy.go
	// of kubernetes. We don't want to end up with tests passing with fake client and
	// failing against the real API server.
	if pod, ok := obj.(*corev1.Pod); ok {
		fs["spec.nodeName"] = pod.Spec.NodeName
	}
	if pod, ok := obj.(*slim_corev1.Pod); ok {
		fs["spec.nodeName"] = pod.Spec.NodeName
	}

	if !selector.Matches(fs) {
		// Check if we failed because we were trying to match a field that doesn't exist.
		// If so, we'll panic so that an exception can be added.
		for _, req := range selector.Requirements() {
			if _, ok := fs[req.Field]; !ok {
				panic(fmt.Sprintf(
					"Unknown field selector %q!\nPlease add handling for it to matchFieldSelector() in test/controlplane/suite/testcase.go",
					req.Field))
			}
		}
		return false
	}
	return true
}

type fakeWithTracker interface {
	PrependReactor(verb string, resource string, reaction k8sTesting.ReactionFunc)
	PrependWatchReactor(resource string, reaction k8sTesting.WatchReactionFunc)
	Tracker() k8sTesting.ObjectTracker
}

type filteringWatcher struct {
	parent       watch.Interface
	events       chan watch.Event
	restrictions k8sTesting.WatchRestrictions
}

var _ watch.Interface = &filteringWatcher{}

func (fw *filteringWatcher) Stop() {
	fw.parent.Stop()
	close(fw.events)
	fw.events = nil
}

func (fw *filteringWatcher) ResultChan() <-chan watch.Event {
	if fw.events != nil {
		return fw.events
	}

	fw.events = make(chan watch.Event)
	selector := fw.restrictions.Fields
	go func() {
		for event := range fw.parent.ResultChan() {
			if matchFieldSelector(event.Object, selector) {
				fw.events <- event
			}
		}
	}()
	return fw.events
}

func filterList(obj k8sRuntime.Object, restrictions k8sTesting.ListRestrictions) {
	selector := restrictions.Fields
	if selector == nil || selector.Empty() {
		return
	}

	switch obj := obj.(type) {
	case *corev1.NodeList:
		items := make([]corev1.Node, 0, len(obj.Items))
		for i := range obj.Items {
			if matchFieldSelector(&obj.Items[i], selector) {
				items = append(items, obj.Items[i])
			}
		}
		obj.Items = items
	case *slim_corev1.NodeList:
		items := make([]slim_corev1.Node, 0, len(obj.Items))
		for i := range obj.Items {
			if matchFieldSelector(&obj.Items[i], selector) {
				items = append(items, obj.Items[i])
			}
		}
		obj.Items = items
	case *slim_corev1.EndpointsList:
		items := make([]slim_corev1.Endpoints, 0, len(obj.Items))
		for i := range obj.Items {
			if matchFieldSelector(&obj.Items[i], selector) {
				items = append(items, obj.Items[i])
			}
		}
		obj.Items = items
	case *slim_corev1.PodList:
		items := make([]slim_corev1.Pod, 0, len(obj.Items))
		for i := range obj.Items {
			if matchFieldSelector(&obj.Items[i], selector) {
				items = append(items, obj.Items[i])
			}
		}
		obj.Items = items
	default:
		panic(
			fmt.Sprintf("Unhandled type %T for field selector filtering!\nPlease add handling for it to filterList()", obj),
		)
	}
}

// addFieldSelection augments the fake clientset to support filtering with a field selector
// in List and Watch actions
func addFieldSelection[T fakeWithTracker](f T) T {
	o := f.Tracker()
	objectReaction := k8sTesting.ObjectReaction(o)

	// Prepend our own reactors that adds field selector filtering to
	// the results.
	f.PrependReactor("*", "*", func(action k8sTesting.Action) (handled bool, ret k8sRuntime.Object, err error) {
		handled, ret, err = objectReaction(action)

		switch action := action.(type) {
		case k8sTesting.ListActionImpl:
			filterList(ret, action.GetListRestrictions())
		}
		return

	})

	f.PrependWatchReactor(
		"*",
		func(action k8sTesting.Action) (handled bool, ret watch.Interface, err error) {
			w := action.(k8sTesting.WatchAction)
			gvr := w.GetResource()
			ns := w.GetNamespace()
			watch, err := o.Watch(gvr, ns)
			if err != nil {
				return false, nil, err
			}
			fw := &filteringWatcher{
				parent:       watch,
				restrictions: w.GetWatchRestrictions(),
			}
			return true, fw, nil

		})

	return f
}
