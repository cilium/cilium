// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitybackend

import (
	"strconv"
	"sync"
	"testing"
	"time"

	. "github.com/cilium/checkmate"
	"golang.org/x/net/context"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/idpool"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1/validation"
	"github.com/cilium/cilium/pkg/labels"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type K8sIdentityBackendSuite struct{}

var _ = Suite(&K8sIdentityBackendSuite{})

func (s *K8sIdentityBackendSuite) TestSanitizeK8sLabels(c *C) {
	path := field.NewPath("test", "labels")
	testCases := []struct {
		input            map[string]string
		selected         map[string]string
		skipped          map[string]string
		validationErrors field.ErrorList
	}{
		{
			input:            map[string]string{},
			selected:         map[string]string{},
			skipped:          map[string]string{},
			validationErrors: field.ErrorList{},
		},
		{
			input:            map[string]string{"k8s:foo": "bar"},
			selected:         map[string]string{"foo": "bar"},
			skipped:          map[string]string{},
			validationErrors: field.ErrorList{},
		},
		{
			input:            map[string]string{"k8s:foo": "bar", "k8s:abc": "def"},
			selected:         map[string]string{"foo": "bar", "abc": "def"},
			skipped:          map[string]string{},
			validationErrors: field.ErrorList{},
		},
		{
			input:            map[string]string{"k8s:foo": "bar", "k8s:abc": "def", "container:something": "else"},
			selected:         map[string]string{"foo": "bar", "abc": "def"},
			skipped:          map[string]string{"container:something": "else"},
			validationErrors: field.ErrorList{},
		},
		{
			input:    map[string]string{"k8s:some.really.really.really.really.really.really.really.long.label.name": "someval"},
			selected: map[string]string{"some.really.really.really.really.really.really.really.long.label.name": "someval"},
			skipped:  map[string]string{},
			validationErrors: field.ErrorList{
				&field.Error{
					Type:     "FieldValueInvalid",
					Field:    "test.labels",
					BadValue: "some.really.really.really.really.really.really.really.long.label.name",
					Detail:   "name part must be no more than 63 characters",
				},
			},
		},
		{
			input:            map[string]string{"k8s:io.cilium.k8s.namespace.labels.some.really.really.long.namespace.label.name": "someval"},
			selected:         map[string]string{},
			skipped:          map[string]string{"k8s:io.cilium.k8s.namespace.labels.some.really.really.long.namespace.label.name": "someval"},
			validationErrors: field.ErrorList{},
		},
	}

	for _, test := range testCases {
		selected, skipped := sanitizeK8sLabels(test.input)
		c.Assert(selected, checker.DeepEquals, test.selected)
		c.Assert(skipped, checker.DeepEquals, test.skipped)
		c.Assert(validation.ValidateLabels(selected, path), checker.DeepEquals, test.validationErrors)
	}
}

type FakeHandler struct {
	onAddFunc func()
}

func (f FakeHandler) OnListDone() {}

func (f FakeHandler) OnAdd(id idpool.ID, key allocator.AllocatorKey) {
	if f.onAddFunc != nil {
		f.onAddFunc()
	}
}

func (f FakeHandler) OnModify(id idpool.ID, key allocator.AllocatorKey) {}

func (f FakeHandler) OnDelete(id idpool.ID, key allocator.AllocatorKey) {}

func getLabelsKey(rawMap map[string]string) allocator.AllocatorKey {
	return &key.GlobalIdentity{LabelArray: labels.Map2Labels(rawMap, labels.LabelSourceK8s).LabelArray()}
}

func getLabelsMap(rawMap map[string]string) map[string]string {
	return getLabelsKey(rawMap).GetAsMap()
}

func createCiliumIdentity(id int, labels map[string]string) v2.CiliumIdentity {
	return v2.CiliumIdentity{
		ObjectMeta: v1.ObjectMeta{
			Name: strconv.Itoa(id),
			CreationTimestamp: v1.Time{
				Time: time.Now(),
			},
		},
		SecurityLabels: getLabelsMap(labels),
	}
}

func TestGetIdentity(t *testing.T) {
	simpleMap := map[string]string{"key": "value"}
	simpleMap2 := map[string]string{"ke2": "value2"}
	simpleMap3 := map[string]string{"key3": "value3"}
	duplicateMap1 := map[string]string{"key": "foo=value"}
	duplicateMap2 := map[string]string{"key=foo": "value"}

	testCases := []struct {
		desc         string
		identities   []v2.CiliumIdentity
		requestedKey allocator.AllocatorKey
		expectedId   string
	}{
		{
			desc:         "Simple case",
			identities:   []v2.CiliumIdentity{createCiliumIdentity(10, simpleMap)},
			requestedKey: getLabelsKey(simpleMap),
			expectedId:   "10",
		},
		{
			desc: "Multiple identities",
			identities: []v2.CiliumIdentity{
				createCiliumIdentity(10, simpleMap),
				createCiliumIdentity(11, simpleMap2),
				createCiliumIdentity(12, simpleMap3),
			},
			requestedKey: getLabelsKey(simpleMap2),
			expectedId:   "11",
		},
		{
			desc: "Duplicated identity",
			identities: []v2.CiliumIdentity{
				createCiliumIdentity(10, duplicateMap1),
				createCiliumIdentity(11, duplicateMap1),
			},
			requestedKey: getLabelsKey(duplicateMap1),
			expectedId:   "10",
		},
		{
			desc: "Duplicated key",
			identities: []v2.CiliumIdentity{
				createCiliumIdentity(10, duplicateMap1),
				createCiliumIdentity(11, duplicateMap2),
			},
			requestedKey: getLabelsKey(duplicateMap2),
			expectedId:   "11",
		},
		{
			desc:         "No identities",
			identities:   []v2.CiliumIdentity{},
			requestedKey: getLabelsKey(simpleMap),
			expectedId:   idpool.NoID.String(),
		},
		{
			desc: "Identity not found",
			identities: []v2.CiliumIdentity{
				createCiliumIdentity(10, simpleMap),
				createCiliumIdentity(11, simpleMap2),
			},
			requestedKey: getLabelsKey(simpleMap3),
			expectedId:   idpool.NoID.String(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			_, client := k8sClient.NewFakeClientset()
			backend, err := NewCRDBackend(CRDBackendConfiguration{
				Store:   nil,
				Client:  client,
				KeyFunc: (&key.GlobalIdentity{}).PutKeyFromMap,
			})
			if err != nil {
				t.Fatalf("Can't create CRD Backend: %s", err)
			}

			ctx := context.Background()
			stopChan := make(chan struct{})
			defer func() {
				close(stopChan)
			}()

			addWaitGroup := sync.WaitGroup{}
			addWaitGroup.Add(len(tc.identities))

			// To avoid a race, we must create these before we start ListAndWatch, see #30873. There
			// is no easy way of knowing when the watch is established. Specifically, 'HasSynced'
			// does _not_ guarantee it: the fake object tracker doesn't do resource versioning and
			// hence cannot replay events in the reflector's gap between list and watch. Ironically,
			// therefore, if we waited for the informer's HasSynced, we'd _increase_ the likelihood
			// of the race. Avoid the whole issue by creating the objects before the informer is
			// even started, thus guaranteeing the objects are part of the initial list.
			for _, identity := range tc.identities {
				_, err = client.CiliumV2().CiliumIdentities().Create(ctx, &identity, v1.CreateOptions{})
				if err != nil {
					t.Fatalf("Can't create identity %s: %s", identity.Name, err)
				}
			}

			go backend.ListAndWatch(ctx, FakeHandler{onAddFunc: func() { addWaitGroup.Done() }}, stopChan)

			// Wait for watcher to process the identities in the background
			addWaitGroup.Wait()

			id, err := backend.Get(ctx, tc.requestedKey)
			if err != nil {
				t.Fatalf("Can't get identity by key %s: %s", tc.requestedKey.GetKey(), err)
			}

			if id == idpool.NoID && tc.expectedId != idpool.NoID.String() {
				t.Errorf("Identity not found in the store")
			}

			if id.String() != tc.expectedId {
				t.Errorf("Expected key %s, got %s", tc.expectedId, id.String())
			}
		})
	}
}
