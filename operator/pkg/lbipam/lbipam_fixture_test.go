package lbipam

import (
	"encoding/json"
	"reflect"
	"time"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	cilium_fake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	jsonpatch "github.com/evanphx/json-patch"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	client_core_v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	k8s_testing "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
)

const (
	poolAUID = types.UID("eb84f074-806e-474e-85c5-001f5780906b")
	poolBUID = types.UID("610a54cf-e0e5-4dc6-ace9-0e6ca9a4aaae")

	serviceAUID = types.UID("b801e1cf-9e71-455c-9bc8-52c0575c22bd")
	serviceBUID = types.UID("b415933e-524c-4f83-8493-de2157fc736f")
	serviceCUID = types.UID("8d820ef0-d640-497a-bc67-b05190bddee6")
)

var (
	servicesResource = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"}
	poolResource     = schema.GroupVersionResource{Group: "cilium.io", Version: "v2alpha1", Resource: "ciliumloadbalancerippools"}
)

type LBIPAMTestFixture struct {
	ciliumCS *cilium_fake.Clientset
	coreCS   *fake.Clientset

	poolClient v2alpha1.CiliumLoadBalancerIPPoolInterface
	svcClient  client_core_v1.ServicesGetter

	hive   *hive.Hive
	lbIPAM *LBIPAM

	poolReactor func(action k8s_testing.Action)
	svcReactor  func(action k8s_testing.Action)
}

func mkTestFixture(pools []*cilium_api_v2alpha1.CiliumLoadBalancerIPPool, ipv4, ipv6 bool, initDone chan struct{}) *LBIPAMTestFixture {
	fixture := &LBIPAMTestFixture{}

	var obj []runtime.Object
	for _, pool := range pools {
		obj = append(obj, (*cilium_api_v2alpha1.CiliumLoadBalancerIPPool)(pool))
	}

	fixture.ciliumCS = cilium_fake.NewSimpleClientset(obj...)
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

	fixture.coreCS = fake.NewSimpleClientset()
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

	fixture.poolClient = fixture.ciliumCS.CiliumV2alpha1().CiliumLoadBalancerIPPools()
	fixture.svcClient = fixture.coreCS.CoreV1()

	flags := pflag.NewFlagSet("", pflag.ContinueOnError)

	fixture.hive = hive.New(
		viper.New(),
		flags,
		cell.Provide(resource.NewResourceConstructor[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool](func(c k8sClient.Clientset) cache.ListerWatcher {
			return utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumLoadBalancerIPPoolList](c.CiliumV2alpha1().CiliumLoadBalancerIPPools())
		})),
		cell.Provide(resource.NewResourceConstructor[*core_v1.Service](func(c k8sClient.Clientset) cache.ListerWatcher {
			return utils.ListerWatcherFromTyped[*core_v1.ServiceList](c.CoreV1().Services(""))
		})),
		cell.Provide(func() k8sClient.Clientset {
			return &k8sClient.FakeClientset{
				KubernetesFakeClientset: fixture.coreCS,
				CiliumFakeClientset:     fixture.ciliumCS,
			}
		}),
		cell.Provide(func() LBIPAMInitDone {
			return initDone
		}),

		cell.Invoke(func(lbIPAM *LBIPAM) {
			fixture.lbIPAM = lbIPAM
		}),

		Cell,
	)

	flags.Set("lb-ipam", "true")

	return fixture
}

type PoolAwait struct {
	block        chan struct{}
	timer        *time.Timer
	savedReactor func(action k8s_testing.Action)
	fixture      *LBIPAMTestFixture
}

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

func (fix *LBIPAMTestFixture) PatchedSvc(action k8s_testing.Action) *core_v1.Service {
	return fix.patchedObj(fix.coreCS.Tracker(), action.(k8s_testing.PatchAction)).(*core_v1.Service)
}

func (fix *LBIPAMTestFixture) PatchedPool(action k8s_testing.Action) *cilium_api_v2alpha1.CiliumLoadBalancerIPPool {
	return fix.patchedObj(fix.ciliumCS.Tracker(), action.(k8s_testing.PatchAction)).(*cilium_api_v2alpha1.CiliumLoadBalancerIPPool)
}

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
