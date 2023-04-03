// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipam

import (
	"encoding/json"
	"reflect"
	"time"

	jsonpatch "github.com/evanphx/json-patch"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	k8s_testing "k8s.io/client-go/testing"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	cilium_fake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_fake "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/fake"
	client_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/typed/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
)

// A list of constants which can be re-used during testing.
const (
	poolAUID = types.UID("eb84f074-806e-474e-85c5-001f5780906b")
	poolBUID = types.UID("610a54cf-e0e5-4dc6-ace9-0e6ca9a4aaae")

	serviceAUID = types.UID("b801e1cf-9e71-455c-9bc8-52c0575c22bd")
	serviceBUID = types.UID("b415933e-524c-4f83-8493-de2157fc736f")
	serviceCUID = types.UID("8d820ef0-d640-497a-bc67-b05190bddee6")
)

var (
	servicesResource = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"}
	poolResource     = schema.GroupVersionResource{
		Group:    cilium_api_v2alpha1.SchemeGroupVersion.Group,
		Version:  cilium_api_v2alpha1.SchemeGroupVersion.Version,
		Resource: cilium_api_v2alpha1.PoolPluralName,
	}
)

// LBIPAMTestFixture is test fixtures which we can use to mock all inputs and outputs of the LB-IPAM cell. This fixture
// gives us the ability to simulate a number of API server states and allows us to register callbacks when LB-IPAM
// writes back to the API server.
type LBIPAMTestFixture struct {
	ciliumCS *cilium_fake.Clientset
	coreCS   *slim_fake.Clientset

	poolClient v2alpha1.CiliumLoadBalancerIPPoolInterface
	svcClient  client_core_v1.ServicesGetter

	hive   *hive.Hive
	lbIPAM *LBIPAM

	poolReactor func(action k8s_testing.Action)
	svcReactor  func(action k8s_testing.Action)
}

func mkTestFixture(pools []*cilium_api_v2alpha1.CiliumLoadBalancerIPPool, ipv4, ipv6 bool, initDone func()) *LBIPAMTestFixture {
	fixture := &LBIPAMTestFixture{}

	// Convert exact pool types to runtime.Object interface so we can insert them.
	var obj []runtime.Object
	for _, pool := range pools {
		obj = append(obj, (*cilium_api_v2alpha1.CiliumLoadBalancerIPPool)(pool))
	}

	// Create a new mocked CRD client set with the pools as initial objects
	fixture.ciliumCS = cilium_fake.NewSimpleClientset(obj...)
	// Create a new reactor, any API call related to IP Pools made to the mocked client will trigger
	// our `fixture.poolReactor` callback if set.
	poolReactor := &k8s_testing.SimpleReactor{
		Verb:     "*",
		Resource: "ciliumloadbalancerippools",
		Reaction: func(action k8s_testing.Action) (handled bool, ret runtime.Object, err error) {
			if fixture.poolReactor != nil {
				fixture.poolReactor(action)
			}
			return false, nil, nil
		},
	}
	fixture.ciliumCS.ReactionChain = append([]k8s_testing.Reactor{poolReactor}, fixture.ciliumCS.ReactionChain...)

	// Create a new mocked core client set
	fixture.coreCS = slim_fake.NewSimpleClientset()
	// / Create a new reactor, any API call related to services made to the mocked client will trigger
	// our `fixture.svcReactor` callback if set.
	svcReactor := &k8s_testing.SimpleReactor{
		Verb:     "*",
		Resource: "services",
		Reaction: func(action k8s_testing.Action) (handled bool, ret runtime.Object, err error) {
			if fixture.svcReactor != nil {
				fixture.svcReactor(action)
			}
			return false, nil, nil
		},
	}
	fixture.coreCS.ReactionChain = append([]k8s_testing.Reactor{svcReactor}, fixture.coreCS.ReactionChain...)

	// Get a pool and service client from the sets.
	fixture.poolClient = fixture.ciliumCS.CiliumV2alpha1().CiliumLoadBalancerIPPools()
	fixture.svcClient = fixture.coreCS.CoreV1()

	// Construct a new Hive with mocked out dependency cells.
	fixture.hive = hive.New(
		// Create a resource from the mocked clients
		cell.Provide(func(lc hive.Lifecycle, c k8sClient.Clientset) resource.Resource[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool] {
			return resource.New[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool](
				lc, utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumLoadBalancerIPPoolList](
					c.CiliumV2alpha1().CiliumLoadBalancerIPPools(),
				),
			)
		}),
		cell.Provide(func(lc hive.Lifecycle, c k8sClient.Clientset) resource.Resource[*slim_core_v1.Service] {
			return resource.New[*slim_core_v1.Service](
				lc, utils.ListerWatcherFromTyped[*slim_core_v1.ServiceList](
					c.Slim().CoreV1().Services(""),
				),
			)
		}),

		// Provide the mocked client cells directly
		cell.Provide(func() k8sClient.Clientset {
			return &k8sClient.FakeClientset{
				SlimFakeClientset:   fixture.coreCS,
				CiliumFakeClientset: fixture.ciliumCS,
			}
		}),

		// Provide an operator config, with the BGP LB announcement flag set, which causes the BGP Control plane
		// LB Class to be added.
		cell.Provide(func() *option.DaemonConfig {
			return &option.DaemonConfig{
				EnableBGPControlPlane: true,
			}
		}),

		// This callback will write the LB-IPAM instance to the fixture so internals can be checked in the tests.
		cell.Invoke(func(lbIPAM *LBIPAM) {
			fixture.lbIPAM = lbIPAM
			if initDone != nil {
				lbIPAM.RegisterOnReady(initDone)
			}
		}),

		job.Cell,

		// Add the actual LB-IPAM cell under test.
		Cell,
	)

	return fixture
}

// PoolAwait can be used to await a certain event or until the timer expires.
type PoolAwait struct {
	block        chan struct{}
	timer        *time.Timer
	savedReactor func(action k8s_testing.Action)
	fixture      *LBIPAMTestFixture
}

// Block blocks the current routine until the reactor callback unblocks or the timeout expires.
func (a *PoolAwait) Block() (timeout bool) {
	select {
	case <-a.block:
		a.timer.Stop()
	case <-a.timer.C:
		select {
		case <-a.block:
		default:
			close(a.block)
		}
		timeout = true
	}

	a.fixture.poolReactor = a.savedReactor

	return timeout
}

// AwaitPool calls `onEvent` on every pool event. This func blocks until onEvent returns true or the timeout expires
func (fix *LBIPAMTestFixture) AwaitPool(onEvent func(action k8s_testing.Action) bool, timeout time.Duration) *PoolAwait {
	await := &PoolAwait{
		block:        make(chan struct{}),
		timer:        time.NewTimer(timeout),
		savedReactor: fix.poolReactor,
		fixture:      fix,
	}

	fix.poolReactor = func(action k8s_testing.Action) {
		if onEvent(action) {
			select {
			case <-await.block:
			default:
				close(await.block)
			}
		}

		if await.savedReactor != nil {
			await.savedReactor(action)
		}
	}

	return await
}

type ServiceAwait struct {
	block        chan struct{}
	timer        *time.Timer
	savedReactor func(action k8s_testing.Action)
	fixture      *LBIPAMTestFixture
}

func (a *ServiceAwait) Block() (timeout bool) {
	select {
	case <-a.block:
		a.timer.Stop()
	case <-a.timer.C:
		select {
		case <-a.block:
		default:
			close(a.block)
		}
		timeout = true
	}

	a.fixture.svcReactor = a.savedReactor

	return timeout
}

// AwaitService calls `onEvent` on every service event. This func blocks until onEvent returns true or the timeout expires
func (fix *LBIPAMTestFixture) AwaitService(onEvent func(action k8s_testing.Action) bool, timeout time.Duration) *ServiceAwait {
	await := &ServiceAwait{
		block:        make(chan struct{}),
		timer:        time.NewTimer(timeout),
		savedReactor: fix.svcReactor,
		fixture:      fix,
	}

	fix.svcReactor = func(action k8s_testing.Action) {
		if onEvent(action) {
			select {
			case <-await.block:
			default:
				close(await.block)
			}
		}

		if await.savedReactor != nil {
			await.savedReactor(action)
		}
	}

	return await
}

// PatchedSvc will apply the patch data contained in the `action` onto the currently known object in the mock client
// and return the patched object.
func (fix *LBIPAMTestFixture) PatchedSvc(action k8s_testing.Action) *slim_core_v1.Service {
	return fix.patchedObj(fix.coreCS.Tracker(), action.(k8s_testing.PatchAction)).(*slim_core_v1.Service)
}

// PatchedPool will apply the patch data contained in the `action` onto the currently known object in the mock client
// and return the patched object.
func (fix *LBIPAMTestFixture) PatchedPool(action k8s_testing.Action) *cilium_api_v2alpha1.CiliumLoadBalancerIPPool {
	return fix.patchedObj(fix.ciliumCS.Tracker(), action.(k8s_testing.PatchAction)).(*cilium_api_v2alpha1.CiliumLoadBalancerIPPool)
}

// patchedObj actually does the abstract patching logic, this function is extracted from the mock client so we can do
// the same logic but before the actual store is updated.
func (fix *LBIPAMTestFixture) patchedObj(tracker k8s_testing.ObjectTracker, action k8s_testing.PatchAction) runtime.Object {
	obj, err := tracker.Get(action.GetResource(), action.GetNamespace(), action.GetName())
	if err != nil {
		panic(err)
	}

	old, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}

	// reset the object in preparation to unmarshal, since unmarshal does not guarantee that fields
	// in obj that are removed by patch are cleared
	value := reflect.ValueOf(obj)
	value.Elem().Set(reflect.New(value.Type().Elem()).Elem())

	switch action.GetPatchType() {
	case types.JSONPatchType:
		patch, err := jsonpatch.DecodePatch(action.GetPatch())
		if err != nil {
			panic(err)
		}
		modified, err := patch.Apply(old)
		if err != nil {
			panic(err)
		}

		if err = json.Unmarshal(modified, obj); err != nil {
			panic(err)
		}
	default:
		panic("Unknown patch type")
	}

	return obj
}

// mkPool is a constructor function to assist in the creation of new pool objects.
func mkPool(uid types.UID, name string, cidrs []string) *cilium_api_v2alpha1.CiliumLoadBalancerIPPool {
	var blocks []cilium_api_v2alpha1.CiliumLoadBalancerIPPoolCIDRBlock
	for _, cidr := range cidrs {
		blocks = append(blocks, cilium_api_v2alpha1.CiliumLoadBalancerIPPoolCIDRBlock{
			Cidr: cilium_api_v2alpha1.IPv4orIPv6CIDR(cidr),
		})
	}

	return &cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:              name,
			UID:               uid,
			CreationTimestamp: meta_v1.Date(2022, 10, 16, 12, 00, 00, 0, time.UTC),
		},
		Spec: cilium_api_v2alpha1.CiliumLoadBalancerIPPoolSpec{
			Cidrs: blocks,
		},
	}
}
