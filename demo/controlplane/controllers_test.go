package controlplane

import (
	"context"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/cilium/cilium/demo/datapath"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/pmezard/go-difflib/difflib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	yamlv3 "gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/fake"
)

// Parameters to extract from the object graph for the test.
// We use the fake clientset to insert objects and then the
// frontend and backend tables to validate the result.
type params struct {
	cell.In

	DB        *statedb.DB
	Clientset *client.FakeClientset
	Frontends statedb.Table[*datapath.Frontend]
	Backends  statedb.Table[*datapath.Backend]
}

type testCase struct {
	name     string
	file     string
	expected string
}

var (
	decoder = func() runtime.Decoder {
		coreScheme := runtime.NewScheme()
		fake.AddToScheme(coreScheme)
		return serializer.NewCodecFactory(coreScheme).UniversalDeserializer()
	}()
)

func parse(data []byte) []runtime.Object {
	// First decode the list of items into an unstructured list.
	var items unstructured.UnstructuredList
	err := yaml.Unmarshal(data, &items)
	if err != nil {
		panic(err)
	}

	// Then decode each unstructured object
	var objs []runtime.Object
	items.EachListItem(func(obj runtime.Object) error {
		uobj, ok := obj.(*unstructured.Unstructured)
		if !ok {
			panic("not unstructured")
		}
		jsonBytes, err := uobj.MarshalJSON()
		if err != nil {
			panic(err)
		}
		obj, _, err = decoder.Decode(jsonBytes, nil, nil)
		if err != nil {
			panic(err)
		}
		objs = append(objs, obj)
		return nil
	})
	return objs
}

type expectedOut struct {
	Frontends []*datapath.Frontend
	Backends  []*datapath.Backend
}

func diffStrings(file string, expected, actual string) (string, bool) {
	diff := difflib.UnifiedDiff{
		A:        difflib.SplitLines(expected),
		B:        difflib.SplitLines(actual),
		FromFile: file,
		ToFile:   "<actual>",
		Context:  10,
	}
	out, err := difflib.GetUnifiedDiffString(diff)
	if err != nil {
		return err.Error(), false
	}
	if out != "" {
		return out, false
	}
	return "", true
}

// TestControlPlane is a golden integration test for the control-plane that validates
// transformations from K8s objects to the datapath desired state.
//
// The purpose of this is to demo how to create an integration test at the control-plane
// layer that validates the processing of external data all the way down to the datapath
// interface (the desired state tables).
//
// A test-case is created by creating directory 'testdata/<name>' and adding the
// input.yaml file containing k8s objects and expected.yaml file containing the
// frontends and backends. The input can be created with: "kubectl get svc ep -o yaml > input.yaml".
// The expected output can be created with "touch expected.yaml". On the first run the
// test will create "actual.yaml" that can be copied to "expected.yaml".
func TestControlPlane(t *testing.T) {
	var testCases []testCase
	ents, err := os.ReadDir("testdata")
	require.NoError(t, err)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".") || !e.IsDir() {
			continue
		}
		testCases = append(testCases, testCase{
			name:     e.Name(),
			file:     path.Join("testdata", e.Name(), "input.yaml"),
			expected: path.Join("testdata", e.Name(), "expected.yaml"),
		})
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var p params

			// Use a fresh hive for each test case for consistent IDs.
			// TODO: could be avoid with further sanitization of the expected/actual data.
			h := hive.New(
				job.Cell,
				statedb.Cell,
				client.FakeClientCell,

				// Output tables
				cell.Provide(
					datapath.NewFrontends,
					datapath.NewBackends,
				),

				tablesCell,
				k8sCell,
				servicesControllerCell,

				cell.Invoke(func(p_ params) { p = p_ }),
			)

			require.NoError(t, h.Start(context.TODO()))
			tracker := p.Clientset.KubernetesFakeClientset.Tracker()

			data, err := os.ReadFile(tc.file)
			require.NoError(t, err, "ReadFile %s", tc.file)
			objs := parse(data)
			for _, obj := range objs {
				tracker.Add(obj)
			}

			var (
				lastDiff   string
				lastActual []byte
			)

			check := func() bool {
				// Collect and sanitize the actual state
				txn := p.DB.ReadTxn()
				iter, _ := p.Frontends.All(txn)
				iter = statedb.Map(iter, func(fe *datapath.Frontend) *datapath.Frontend {
					fe = fe.Clone()
					fe.Status.UpdatedAt = time.Time{}
					return fe
				})
				frontends := statedb.Collect(iter)
				iter2, _ := p.Backends.All(txn)
				iter2 = statedb.Map(iter2, func(be *datapath.Backend) *datapath.Backend {
					be = be.Clone()
					be.Status.UpdatedAt = time.Time{}
					return be
				})
				backends := statedb.Collect(iter2)

				actual := expectedOut{
					Frontends: frontends,
					Backends:  backends,
				}
				var expected expectedOut

				expectedBytes, err := os.ReadFile(tc.expected)
				require.NoError(t, err, "ReadFile(%s)", tc.expected)
				err = yamlv3.Unmarshal(expectedBytes, &expected)
				require.NoError(t, err, "Unmarshal(%s)", tc.expected)

				lastActual, err = yamlv3.Marshal(actual)
				require.NoError(t, err, "Marshal(actual)")

				var ok bool
				lastDiff, ok = diffStrings(tc.expected, string(expectedBytes), string(lastActual))
				return ok
			}

			if !assert.Eventually(
				t,
				check,
				time.Second,
				50*time.Millisecond,
			) {
				actualFile := path.Join("testdata", tc.name, "actual.yaml")
				os.WriteFile(actualFile, lastActual, 0644)
				t.Logf("Could not reach expected state. Wrote the last state to %s", actualFile)
				t.Logf("Diff:\n%s", lastDiff)
			}

			// Delete everything and wait for cleanup.
			for _, obj := range objs {
				gvr, ns, name := gvrAndName(obj)
				tracker.Delete(gvr, ns, name)
			}

			require.Eventually(
				t,
				func() bool {
					txn := p.DB.ReadTxn()
					numFrontends := p.Frontends.NumObjects(txn)
					numBackends := p.Backends.NumObjects(txn)
					return numFrontends == 0 && numBackends == 0
				},
				time.Second,
				50*time.Millisecond,
				"Expected frontends and backends to be deleted",
			)
			require.NoError(t, h.Stop(context.TODO()))
		})
	}

}

func gvrAndName(obj runtime.Object) (gvr schema.GroupVersionResource, ns string, name string) {
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
