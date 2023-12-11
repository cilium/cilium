// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipam

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime/debug"
	"testing"
	"time"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	client_typed_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/typed/core/v1"
)

// A list of constants which can be re-used during testing.
const (
	poolAUID = types.UID("eb84f074-806e-474e-85c5-001f5780906b")
	poolBUID = types.UID("610a54cf-e0e5-4dc6-ace9-0e6ca9a4aaae")

	serviceAUID = types.UID("b801e1cf-9e71-455c-9bc8-52c0575c22bd")
	serviceBUID = types.UID("b415933e-524c-4f83-8493-de2157fc736f")
	serviceCUID = types.UID("8d820ef0-d640-497a-bc67-b05190bddee6")
)

type fakeIPPoolClient struct {
	resources map[resource.Key]*v2alpha1.CiliumLoadBalancerIPPool
}

func (fic *fakeIPPoolClient) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2alpha1.CiliumLoadBalancerIPPool, err error) {
	existing, found := fic.resources[resource.Key{Name: name}]
	if !found {
		return nil, fmt.Errorf("No IP pool found with name %q", name)
	}

	old, err := json.Marshal(existing)
	if err != nil {
		panic(err)
	}

	// reset the object in preparation to unmarshal, since unmarshal does not guarantee that fields
	// in obj that are removed by patch are cleared
	value := reflect.ValueOf(existing)
	value.Elem().Set(reflect.New(value.Type().Elem()).Elem())

	var obj cilium_api_v2alpha1.CiliumLoadBalancerIPPool

	switch pt {
	case types.JSONPatchType:
		patch, err := jsonpatch.DecodePatch(data)
		if err != nil {
			panic(err)
		}
		modified, err := patch.Apply(old)
		if err != nil {
			panic(err)
		}

		if err = json.Unmarshal(modified, &obj); err != nil {
			panic(err)
		}
	default:
		panic("Unknown patch type")
	}

	fic.resources[resource.Key{Name: name}] = &obj

	return &obj, nil
}

type fakeSvcClientGetter struct {
	resources map[resource.Key]*slim_core_v1.Service
}

func (fscg *fakeSvcClientGetter) Services(namespace string) client_typed_v1.ServiceInterface {
	return &fakeSvcClient{
		namespace: namespace,
		getter:    fscg,
	}
}

type fakeSvcClient struct {
	namespace string
	getter    *fakeSvcClientGetter
}

func (fsc *fakeSvcClient) Create(ctx context.Context, service *slim_core_v1.Service, opts metav1.CreateOptions) (*slim_core_v1.Service, error) {
	return nil, nil
}
func (fsc *fakeSvcClient) Update(ctx context.Context, service *slim_core_v1.Service, opts metav1.UpdateOptions) (*slim_core_v1.Service, error) {
	return nil, nil
}
func (fsc *fakeSvcClient) UpdateStatus(ctx context.Context, service *slim_core_v1.Service, opts metav1.UpdateOptions) (*slim_core_v1.Service, error) {
	return nil, nil
}
func (fsc *fakeSvcClient) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return nil
}
func (fsc *fakeSvcClient) Get(ctx context.Context, name string, opts metav1.GetOptions) (*slim_core_v1.Service, error) {
	return nil, nil
}
func (fsc *fakeSvcClient) List(ctx context.Context, opts metav1.ListOptions) (*slim_core_v1.ServiceList, error) {
	return nil, nil
}
func (fsc *fakeSvcClient) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return nil, nil
}

func (fsc *fakeSvcClient) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *slim_core_v1.Service, err error) {
	existing, found := fsc.getter.resources[resource.Key{Namespace: fsc.namespace, Name: name}]
	if !found {
		return nil, fmt.Errorf("No service found with name %q", name)
	}

	old, err := json.Marshal(existing)
	if err != nil {
		panic(err)
	}

	// reset the object in preparation to unmarshal, since unmarshal does not guarantee that fields
	// in obj that are removed by patch are cleared
	value := reflect.ValueOf(existing)
	value.Elem().Set(reflect.New(value.Type().Elem()).Elem())

	var obj slim_core_v1.Service

	switch pt {
	case types.JSONPatchType:
		patch, err := jsonpatch.DecodePatch(data)
		if err != nil {
			panic(err)
		}
		modified, err := patch.Apply(old)
		if err != nil {
			panic(err)
		}

		if err = json.Unmarshal(modified, &obj); err != nil {
			panic(err)
		}
	default:
		panic("Unknown patch type")
	}

	fsc.getter.resources[resource.Key{Namespace: fsc.namespace, Name: name}] = &obj

	return &obj, nil
}

type newFixture struct {
	lbipam *LBIPAM

	// mock clients
	poolClient *fakeIPPoolClient
	svcClient  *fakeSvcClientGetter
}

func (nf *newFixture) GetPool(name string) *v2alpha1.CiliumLoadBalancerIPPool {
	return nf.poolClient.resources[resource.Key{Name: name}]
}

func (nf *newFixture) UpsertPool(t *testing.T, pool *v2alpha1.CiliumLoadBalancerIPPool) {
	key := resource.Key{Name: pool.Name}
	nf.poolClient.resources[key] = pool
	nf.lbipam.handlePoolEvent(context.Background(), resource.Event[*v2alpha1.CiliumLoadBalancerIPPool]{
		Kind:   resource.Upsert,
		Key:    key,
		Object: pool,
		Done: func(err error) {
			if err != nil {
				t.Fatal(err)
			}
		},
	})
}

func (nf *newFixture) DeletePool(t *testing.T, pool *v2alpha1.CiliumLoadBalancerIPPool) {
	key := resource.Key{Name: pool.Name}
	delete(nf.poolClient.resources, key)
	nf.lbipam.handlePoolEvent(context.Background(), resource.Event[*v2alpha1.CiliumLoadBalancerIPPool]{
		Kind:   resource.Delete,
		Key:    key,
		Object: pool,
		Done: func(err error) {
			if err != nil {
				t.Fatal(err)
			}
		},
	})
}

func (nf *newFixture) UpsertSvc(t *testing.T, svc *slim_core_v1.Service) {
	key := resource.Key{Name: svc.Name, Namespace: svc.Namespace}
	nf.svcClient.resources[key] = svc
	nf.lbipam.handleServiceEvent(context.Background(), resource.Event[*slim_core_v1.Service]{
		Kind:   resource.Upsert,
		Key:    key,
		Object: svc,
		Done: func(err error) {
			if err != nil {
				debug.PrintStack()
				t.Fatal(err)
			}
		},
	})
}

func (nf *newFixture) DeleteSvc(t *testing.T, svc *slim_core_v1.Service) {
	key := resource.Key{Name: svc.Name, Namespace: svc.Namespace}
	delete(nf.svcClient.resources, key)
	nf.lbipam.handleServiceEvent(context.Background(), resource.Event[*slim_core_v1.Service]{
		Kind:   resource.Delete,
		Key:    key,
		Object: svc,
		Done: func(err error) {
			if err != nil {
				t.Fatal(err)
			}
		},
	})
}

func (nf *newFixture) GetSvc(namespace, name string) *slim_core_v1.Service {
	return nf.svcClient.resources[resource.Key{Namespace: namespace, Name: name}]
}

func mkTestFixture(ipv4Enabled, ipv6Enabled bool) newFixture {
	log := logrus.New()
	if testing.Verbose() {
		log.SetLevel(logrus.DebugLevel)
	} else {
		log.SetLevel(logrus.ErrorLevel)
	}

	poolClient := &fakeIPPoolClient{
		resources: make(map[resource.Key]*v2alpha1.CiliumLoadBalancerIPPool),
	}
	svcClient := &fakeSvcClientGetter{
		resources: make(map[resource.Key]*slim_core_v1.Service),
	}

	return newFixture{
		poolClient: poolClient,
		svcClient:  svcClient,
		lbipam: newLBIPAM(lbIPAMParams{
			logger: log,
			lbClasses: []string{
				cilium_api_v2alpha1.BGPLoadBalancerClass,
				cilium_api_v2alpha1.L2AnnounceLoadBalancerClass,
			},
			ipv4Enabled: ipv4Enabled,
			ipv6Enabled: ipv6Enabled,

			metrics: newMetrics(),

			poolClient: poolClient,
			svcClient:  svcClient,
		}),
	}
}

// mkPool is a constructor function to assist in the creation of new pool objects.
func mkPool(uid types.UID, name string, cidrs []string) *cilium_api_v2alpha1.CiliumLoadBalancerIPPool {
	var blocks []cilium_api_v2alpha1.CiliumLoadBalancerIPPoolIPBlock
	for _, cidr := range cidrs {
		blocks = append(blocks, cilium_api_v2alpha1.CiliumLoadBalancerIPPoolIPBlock{
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
