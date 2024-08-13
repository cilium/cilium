// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dynamicconfig

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/health/types"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/testutils"
)

var (
	cmName    = "cilium-config"
	namespace = "kube-system"
)

func TestComputeConfigMap(t *testing.T) {
	dummyConfigMap := map[string]string{"key1": "value1", "key2": "value2"}

	testCases := []struct {
		name           string
		cm             *v1.ConfigMap
		expectedConfig map[string]string
	}{
		{
			name:           "default",
			cm:             buildConfigMap(dummyConfigMap),
			expectedConfig: dummyConfigMap,
		},
		{
			name:           "empty",
			cm:             buildConfigMap(map[string]string{}),
			expectedConfig: map[string]string{},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, db, table, fakeClient, cmResource := fixture(t)
			ctx := context.Background()

			_, err := fakeClient.CoreV1().ConfigMaps(namespace).Create(ctx, tc.cm, metav1.CreateOptions{})
			if err != nil {
				t.Errorf("creating CofigMap: %v", err)
			}

			store, err := (*cmResource).Store(ctx)
			if err != nil {
				t.Errorf("init cmResource store: %v", err)
			}

			if err := testutils.WaitUntil(func() bool {
				return len(store.List()) > 0
			}, 2*time.Second); err != nil {
				t.Errorf("waiting for configmap: %v", err)
			}

			var gotMap map[string]string
			if err := testutils.WaitUntil(func() bool {
				gotMap = iterToMap(table.All(db.ReadTxn()))
				return len(gotMap) == len(tc.expectedConfig)
			}, 2*time.Second); err != nil {
				t.Errorf("waiting for confing table: %v", err)
			}

			if !reflect.DeepEqual(gotMap, tc.expectedConfig) {
				t.Errorf("expectedConfig:\n%+v\ngot:\n%+v", tc.expectedConfig, gotMap)
			}
		})
	}
}

func iterToMap(iter statedb.Iterator[*ConfigEntry]) map[string]string {
	m := make(map[string]string)
	for {
		s, _, ok := iter.Next()
		if !ok {
			break
		}
		m[s.Key] = s.Value
	}
	return m
}

func buildConfigMap(data map[string]string) *v1.ConfigMap {
	return &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: namespace,
		},
		Data: data,
	}
}

func fixture(t *testing.T) (*hive.Hive, *statedb.DB, statedb.RWTable[*ConfigEntry], *k8sClient.FakeClientset, *k8s.DynamicConfigMapResource) {
	var (
		db              *statedb.DB
		table           statedb.RWTable[*ConfigEntry]
		ciliumConfigMap *k8s.DynamicConfigMapResource
		fakeClient      *k8sClient.FakeClientset
	)

	h := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		cell.Provide(
			NewConfigTable,
			func(table statedb.RWTable[*ConfigEntry]) statedb.Table[*ConfigEntry] {
				return table
			},
			func(lc cell.Lifecycle, p types.Provider, jr job.Registry) job.Group {
				h := p.ForModule(cell.FullModuleID{"test"})
				jg := jr.NewGroup(h)
				lc.Append(jg)
				return jg
			},
			func() config {
				return config{
					EnableDynamicConfig: true,
				}
			}),
		cell.Invoke(
			func(t statedb.RWTable[*ConfigEntry], p controllerParams, lcm k8s.DynamicConfigMapResource, db_ *statedb.DB, c *k8sClient.FakeClientset) error {
				table = t
				ciliumConfigMap = &lcm
				db = db_
				fakeClient = c
				registerController(table, p)
				return nil
			},
			statedb.RegisterTable[*ConfigEntry],
		),
	)

	ctx := context.Background()
	tLog := hivetest.Logger(t)
	if err := h.Start(tLog, ctx); err != nil {
		t.Fatalf("starting hive encountered: %s", err)
	}
	t.Cleanup(func() {
		if err := h.Stop(tLog, ctx); err != nil {
			t.Fatalf("stoping hive encountered: %s", err)
		}
	})

	return h, db, table, fakeClient, ciliumConfigMap
}
