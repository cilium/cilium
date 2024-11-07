// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dynamicconfig

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/health/types"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/option/resolver"
	"github.com/cilium/cilium/pkg/testutils"
)

var (
	cmName         = "cilium-config"
	namespace      = "kube-system"
	dummyConfigMap = map[string]string{"key1": "value1", "key2": "value2"}
)

func TestWatchAllKeys(t *testing.T) {
	cSource := `[{"kind":"config-map","namespace":"kube-system","name":"a-low-priority"},{"kind":"config-map","namespace":"kube-system","name":"cilium-config"}]`
	expected := map[string]DynamicConfig{
		"key": {
			Key: Key{
				Name:   "key",
				Source: "cilium-config",
			},
			Value:    "newValue",
			Priority: 0,
		},
	}
	_, db, dct, _ := fixture(t, cSource)

	key := "key"
	lowPrioritySource := "a-low-priority" // leading 'a' to test that sources that are not in priority map have lower priority
	value := "value"
	newValue := "newValue"

	upsertDummyEntry(db, dct, key, lowPrioritySource, value, 1)
	_, w := WatchAllKeys(db.ReadTxn(), dct)
	upsertDummyEntry(db, dct, key, cmName, newValue, 0)
	select {
	case <-w:
	case <-time.After(2 * time.Second):
		t.Fatal("WatchKey() failed to detect changes")
	}

	keys, _ := WatchAllKeys(db.ReadTxn(), dct)
	if !reflect.DeepEqual(keys, expected) {
		t.Errorf("WatchAllKeys returned unexpected result. Got: %v, Expected: %v", keys, expected)
	}
}

func TestWatchKey(t *testing.T) {
	cSource := `[{"kind":"config-map","namespace":"kube-system","name":"a-low-priority"},{"kind":"config-map","namespace":"kube-system","name":"cilium-config"}]`
	_, db, dct, _ := fixture(t, cSource)

	key := "key"
	lowPrioritySource := "a-low-priority" // leading 'a' to test that sources that are not in priority map have lower priority
	value := "value"
	newValue := "newValue"

	upsertDummyEntry(db, dct, key, lowPrioritySource, value, 1)

	e, f, w := WatchKey(db.ReadTxn(), dct, key)
	if !f || e.Key.Name != key || e.Value != value || e.Key.Source != lowPrioritySource {
		t.Errorf("Entry mismatch for key %v: expected (key=%v, source=%v, value=%v), but got (key=%v, source=%v, value=%v)", key, key, lowPrioritySource, value, e.Key.Name, e.Key.Source, e.Value)
	}

	upsertDummyEntry(db, dct, key, cmName, newValue, 0)

	select {
	case <-w:
	case <-time.After(2 * time.Second):
		t.Fatal("WatchKey() failed to detect changes")
	}

	e, f, _ = WatchKey(db.ReadTxn(), dct, key)
	if !f || e.Key.Name != key || e.Value != newValue || e.Key.Source != cmName {
		t.Errorf("Entry mismatch for key %v: expected (key=%v, source=%v, value=%v), but got (key=%v, source=%v, value=%v, priority=%v)", key, key, cmName, value, e.Key.Name, e.Key.Source, e.Value, e.Priority)
	}
}

func TestGetKey(t *testing.T) {
	cSource := `[{"kind":"config-map","namespace":"kube-system","name":"a-low-priority"},{"kind":"config-map","namespace":"kube-system","name":"cilium-config"}]`
	_, db, dct, _ := fixture(t, cSource)

	key := "key"
	lowPrioritySource := "a-low-priority"
	value := "value"
	newValue := "newValue"

	upsertDummyEntry(db, dct, key, lowPrioritySource, value, 1)

	e, f := GetKey(db.ReadTxn(), dct, key)
	if !f || e.Key.Name != key || e.Value != value || e.Key.Source != lowPrioritySource {
		t.Errorf("Entry mismatch: expected (key=%v, source=%v, value=%v), but got (key=%v, source=%v, value=%v)", key, lowPrioritySource, value, e.Key.Name, e.Key.Source, e.Value)
	}

	upsertDummyEntry(db, dct, key, cmName, newValue, 0)

	e, f = GetKey(db.ReadTxn(), dct, key)
	if !f || e.Key.Name != key || e.Value != newValue || e.Key.Source != cmName {
		t.Errorf("Entry mismatch: expected (key=%v, source=%v, value=%v), but got (key=%v, source=%v, value=%v)", key, cmName, newValue, e.Key.Name, e.Key.Source, e.Value)
	}
}

func TestDynamicConfigMap(t *testing.T) {

	testCases := []struct {
		name             string
		cms              []*v1.ConfigMap
		configSources    []resolver.ConfigSource
		expectedConfig   map[string]string
		expectedPriority map[string]int
	}{
		{
			name: "default",
			cms: []*v1.ConfigMap{
				buildConfigMap(cmName, dummyConfigMap),
				buildConfigMap("override-priority", dummyConfigMap),
			},
			configSources: []resolver.ConfigSource{
				{Kind: resolver.KindConfigMap, Namespace: namespace, Name: cmName},
				{Kind: resolver.KindConfigMap, Namespace: namespace, Name: "override-priority"},
			},
			expectedConfig: map[string]string{
				"key1/cilium-config":     "value1",
				"key1/override-priority": "value1",
				"key2/cilium-config":     "value2",
				"key2/override-priority": "value2",
			},
		},
		{
			name: "empty",
			configSources: []resolver.ConfigSource{
				{Kind: resolver.KindConfigMap, Namespace: namespace, Name: cmName},
			},
			cms: []*v1.ConfigMap{
				buildConfigMap(cmName, map[string]string{}),
			},
			expectedConfig: map[string]string{},
		},
		{
			name: "no_config_map",
			configSources: []resolver.ConfigSource{
				{Kind: resolver.KindConfigMap, Namespace: namespace, Name: cmName},
			},
			cms: []*v1.ConfigMap{
				buildConfigMap("other_name", map[string]string{}),
			},
			expectedConfig: map[string]string{},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			configSources, _ := json.Marshal(tc.configSources)

			_, db, dct, cs := fixture(t, string(configSources))

			for _, cm := range tc.cms {
				_, err := cs.CoreV1().ConfigMaps(namespace).Create(ctx, cm, metav1.CreateOptions{})
				if err != nil {
					t.Errorf("creating CofigMap: %v", err)
				}
			}

			gotMap := map[string]string{}
			if err := testutils.WaitUntil(func() bool {
				for obj := range dct.All(db.ReadTxn()) {
					gotMap[obj.Key.String()] = obj.Value
				}
				return len(gotMap) == len(tc.expectedConfig)
			}, 2*time.Second); err != nil {
				t.Errorf("waiting for confing table: %v", err)
			}

			if !reflect.DeepEqual(gotMap, tc.expectedConfig) {
				t.Errorf("expectedConfig:\n%+v\ngot:\n%+v", tc.expectedConfig, gotMap)
			}

			for _, cm := range tc.cms {
				for k, v := range cm.Data {
					obj, _, found := dct.Get(db.ReadTxn(), ByKey(Key{Name: k, Source: cm.Name}))
					if !found || obj.Value != v || obj.Key.Source != cm.Name || obj.Key.Name != k {
						t.Errorf("Entry mismatch: expected (key=%v, source=%v, value=%v), but got (key=%v, source=%v, value=%v)", k, cm.Name, v, obj.Key.Name, obj.Key.Source, obj.Value)
					}
				}
			}
		})
	}
}

func fixture(t *testing.T, sources string) (*hive.Hive, *statedb.DB, statedb.RWTable[DynamicConfig], *k8sClient.FakeClientset) {
	var (
		db         *statedb.DB
		table      statedb.RWTable[DynamicConfig]
		fakeClient *k8sClient.FakeClientset
	)

	h := hive.New(
		k8sClient.FakeClientCell,
		cell.Provide(
			NewConfigTable,
			NewConfigMapReflector,
			func(table statedb.RWTable[DynamicConfig]) statedb.Table[DynamicConfig] {
				return table
			},
			func(lc cell.Lifecycle, p types.Provider, jr job.Registry) job.Group {
				h := p.ForModule(cell.FullModuleID{"test"})
				jg := jr.NewGroup(h)
				lc.Append(jg)
				return jg
			},
			func() Config {
				return Config{
					EnableDynamicConfig:    true,
					ConfigSources:          sources,
					ConfigSourcesOverrides: "{\"allowConfigKeys\":null,\"denyConfigKeys\":null}",
				}
			}),
		cell.Invoke(
			RegisterConfigMapReflector,
			func(t statedb.RWTable[DynamicConfig], db_ *statedb.DB, c *k8sClient.FakeClientset) error {
				table = t
				db = db_
				fakeClient = c
				return nil
			},
		),
	)

	ctx := context.Background()
	tLog := hivetest.Logger(t)
	if err := h.Start(tLog, ctx); err != nil {
		t.Fatalf("starting hive encountered: %s", err)
	}
	t.Cleanup(func() {
		if err := h.Stop(tLog, ctx); err != nil {
			t.Fatalf("stopping hive encountered: %s", err)
		}
	})

	return h, db, table, fakeClient
}

func buildConfigMap(name string, data map[string]string) *v1.ConfigMap {
	return &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: data,
	}
}

func upsertDummyEntry(db *statedb.DB, table statedb.RWTable[DynamicConfig], k string, s string, v string, priority int) {
	txn := db.WriteTxn(table)
	defer txn.Commit()

	entry := DynamicConfig{Key: Key{Name: k, Source: s}, Value: v, Priority: priority}
	_, _, _ = table.Insert(txn, entry)
}
