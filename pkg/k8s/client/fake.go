// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"unsafe"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"
	apiext_fake "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/discovery"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8sTesting "k8s.io/client-go/testing"
	mcsapi_fake "sigs.k8s.io/mcs-api/pkg/client/clientset/versioned/fake"
	k8sYaml "sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/container"
	cilium_fake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	slim_clientset "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned"
	slim_fake "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/k8s/testutils"
)

var FakeClientCell = cell.Module(
	"k8s-fake-client",
	"Fake Kubernetes client",

	cell.ProvidePrivate(
		newStateDBObjectTracker,
	),

	cell.Provide(
		NewFakeClientsetWithTracker,
		func(fc *FakeClientset) hive.ScriptCmdsOut {
			return hive.NewScriptCmds(FakeClientCommands(fc))
		},
	),
)

type (
	MCSAPIFakeClientset     = mcsapi_fake.Clientset
	KubernetesFakeClientset = fake.Clientset
	SlimFakeClientset       = slim_fake.Clientset
	CiliumFakeClientset     = cilium_fake.Clientset
	APIExtFakeClientset     = apiext_fake.Clientset
)

type FakeClientset struct {
	disabled bool

	*MCSAPIFakeClientset
	*KubernetesFakeClientset
	*CiliumFakeClientset
	*APIExtFakeClientset
	clientsetGetters

	SlimFakeClientset *SlimFakeClientset

	trackers []struct {
		domain  string
		tracker k8sTesting.ObjectTracker
	}
}

var _ Clientset = &FakeClientset{}

func (c *FakeClientset) Slim() slim_clientset.Interface {
	return c.SlimFakeClientset
}

func (c *FakeClientset) Discovery() discovery.DiscoveryInterface {
	return c.KubernetesFakeClientset.Discovery()
}

func (c *FakeClientset) IsEnabled() bool {
	return !c.disabled
}

func (c *FakeClientset) Disable() {
	c.disabled = true
}

func (c *FakeClientset) Config() Config {
	//exhaustruct:ignore
	return Config{}
}

func (c *FakeClientset) RestConfig() *rest.Config {
	//exhaustruct:ignore
	return &rest.Config{}
}

func NewFakeClientset(log *slog.Logger) (*FakeClientset, Clientset) {
	return NewFakeClientsetWithTracker(log, nil)
}

func NewFakeClientsetWithTracker(log *slog.Logger, ot *statedbObjectTracker) (*FakeClientset, Clientset) {
	version := testutils.DefaultVersion
	return NewFakeClientsetWithVersion(log, ot, version)
}

func NewFakeClientsetWithVersion(log *slog.Logger, ot *statedbObjectTracker, version string) (*FakeClientset, Clientset) {
	if version == "" {
		version = testutils.DefaultVersion
	}

	if ot == nil {
		// For easier use in tests we'll allow a nil [ot] and just create
		// it from scratch here. We don't do that by default since we do
		// want to use the main StateDB instance to make 'k8s-object-tracker'
		// table inspectable.
		db := statedb.New()
		var err error
		ot, err = newStateDBObjectTracker(db, log)
		if err != nil {
			panic(err)
		}
	}

	resources, found := testutils.APIResources[version]
	if !found {
		panic("version " + version + " not found from testutils.APIResources")
	}

	client := FakeClientset{
		SlimFakeClientset:       slim_fake.NewSimpleClientset(),
		CiliumFakeClientset:     cilium_fake.NewSimpleClientset(),
		APIExtFakeClientset:     apiext_fake.NewSimpleClientset(),
		MCSAPIFakeClientset:     mcsapi_fake.NewSimpleClientset(),
		KubernetesFakeClientset: fake.NewSimpleClientset(),
	}
	client.KubernetesFakeClientset.Resources = resources
	client.SlimFakeClientset.Resources = resources
	client.CiliumFakeClientset.Resources = resources
	client.APIExtFakeClientset.Resources = resources

	otx := ot.For("*", testutils.Scheme, testutils.Decoder())
	prependReactors(client.SlimFakeClientset, otx)
	prependReactors(client.CiliumFakeClientset, otx)
	prependReactors(client.MCSAPIFakeClientset, otx)
	prependReactors(client.APIExtFakeClientset, otx)

	// Use a separate object tracker domain for the "kubernetes" objects. This is needed
	// to avoid overlap with the Slim clientset since they have the same GVR but different
	// Go types.
	otk := ot.For("k8s", testutils.KubernetesScheme, testutils.KubernetesDecoder())
	prependReactors(client.KubernetesFakeClientset, otk)

	client.trackers = []struct {
		domain  string
		tracker k8sTesting.ObjectTracker
	}{
		{domain: "*", tracker: otx},
		{domain: "k8s", tracker: otk},
	}

	fd := client.KubernetesFakeClientset.Discovery().(*fakediscovery.FakeDiscovery)
	fd.FakedServerVersion = toVersionInfo(version)

	client.clientsetGetters = clientsetGetters{&client}
	return &client, &client
}

var FakeClientBuilderCell = cell.Group(
	cell.ProvidePrivate(newStateDBObjectTracker),
	cell.Provide(FakeClientBuilder),
)

func FakeClientBuilder(log *slog.Logger, ot *statedbObjectTracker) ClientBuilderFunc {
	fc, _ := NewFakeClientsetWithTracker(log, ot)
	return func(_ string) (Clientset, error) {
		return fc, nil
	}
}

type prepender interface {
	PrependReactor(verb string, resource string, reaction k8sTesting.ReactionFunc)
	PrependWatchReactor(resource string, reaction k8sTesting.WatchReactionFunc)
	Tracker() k8sTesting.ObjectTracker
}

func prependReactors(cs prepender, ot *statedbObjectTracker) {
	cs.PrependReactor("*", "*", k8sTesting.ObjectReaction(ot))
	cs.PrependWatchReactor("*", func(action k8sTesting.Action) (handled bool, ret watch.Interface, err error) {
		var opts metav1.ListOptions
		if watchAction, ok := action.(k8sTesting.WatchActionImpl); ok {
			opts = watchAction.ListOptions
		}
		gvr := action.GetResource()
		ns := action.GetNamespace()
		watch, err := ot.Watch(gvr, ns, opts)
		if err != nil {
			return false, nil, err
		}
		return true, watch, nil
	})

	// Switch out the tracker to our version.
	overrideTracker(cs, ot)
}

func showGVR(gvr schema.GroupVersionResource) string {
	if gvr.Group == "" {
		return fmt.Sprintf("%s.%s", gvr.Version, gvr.Resource)
	}
	return fmt.Sprintf("%s.%s.%s", gvr.Group, gvr.Version, gvr.Resource)
}

func FakeClientCommands(fc *FakeClientset) map[string]script.Cmd {
	// Use a InsertOrderedMap to keep e.g. k8s/summary output stable.
	seenResources := container.NewInsertOrderedMap[schema.GroupVersionKind, schema.GroupVersionResource]()

	addUpdateOrDelete := func(s *script.State, action string, files []string) error {
		for _, file := range files {
			b, err := os.ReadFile(s.Path(file))
			if err != nil {
				// Try relative to current directory, e.g. to allow reading "testdata/foo.yaml"
				b, err = os.ReadFile(file)
			}
			if err != nil {
				return fmt.Errorf("failed to read %s: %w", file, err)
			}
			obj, gvk, err := testutils.DecodeObjectGVK(b)
			if err != nil {
				return fmt.Errorf("decode: %w", err)
			}
			kobj, _, _ := testutils.DecodeKubernetesObject(b)
			gvr, _ := meta.UnsafeGuessKindToResource(*gvk)
			objMeta, err := meta.Accessor(obj)
			if err != nil {
				return fmt.Errorf("accessor: %w", err)
			}
			seenResources.Insert(*gvk, gvr)

			name := objMeta.GetName()
			ns := objMeta.GetNamespace()

			// Try to add the object to all the trackers. If one of them
			// accepts we're good. We'll add to all since multiple trackers
			// may accept (e.g. slim and kubernetes).

			// err will get set to nil if any of the tracker methods succeed.
			// start with a non-nil default error.
			err = fmt.Errorf("none of the trackers of FakeClientset accepted %T", obj)
			for _, tc := range fc.trackers {
				o := obj
				if tc.domain == "k8s" {
					o = kobj
					if o == nil {
						continue
					}
				}
				var trackerErr error
				switch action {
				case "add":
					trackerErr = tc.tracker.Add(o)
				case "update":
					trackerErr = tc.tracker.Update(gvr, o, ns)
				case "delete":
					trackerErr = tc.tracker.Delete(gvr, ns, name)
				}
				if err != nil {
					if trackerErr == nil {
						// One of the trackers accepted the object, it's a success!
						err = nil
					} else {
						err = errors.Join(err, fmt.Errorf("%s: %w", tc.domain, trackerErr))
					}
				}
			}
			if err != nil {
				return err
			}
		}
		return nil
	}

	return map[string]script.Cmd{
		"k8s/add": script.Command(
			script.CmdUsage{
				Summary: "Add new K8s object(s) to the object trackers",
				Detail: []string{
					"The files should be YAML, e.g. in the format produced by",
					"'kubectl get -o yaml'",
				},
				Args: "files...",
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) == 0 {
					return nil, script.ErrUsage
				}

				return nil, addUpdateOrDelete(s, "add", args)
			},
		),

		"k8s/update": script.Command(
			script.CmdUsage{
				Summary: "Update K8s object(s) in the object trackers",
				Args:    "files...",
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) == 0 {
					return nil, script.ErrUsage
				}
				return nil, addUpdateOrDelete(s, "update", args)
			},
		),

		"k8s/delete": script.Command(
			script.CmdUsage{
				Summary: "Delete K8s object(s) from the object trackers",
				Args:    "files...",
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) == 0 {
					return nil, script.ErrUsage
				}
				return nil, addUpdateOrDelete(s, "delete", args)
			},
		),

		"k8s/get": script.Command(
			script.CmdUsage{
				Summary: "Get a K8s object from the object trackers",
				Detail: []string{
					"Tries object trackers in order. Prefers the slim over kubernetes.",
					"For list of resources run 'k8s/resources'",
				},
				Args: "resource name",
				Flags: func(fs *pflag.FlagSet) {
					fs.StringP("out", "o", "", "File to write to instead of stdout")
				},
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				file, err := s.Flags.GetString("out")
				if err != nil {
					return nil, err
				}
				if len(args) != 2 {
					return nil, script.ErrUsage
				}

				var gvr schema.GroupVersionResource
				for _, r := range seenResources.All() {
					res := showGVR(r)
					if res == args[0] {
						gvr = r
						break
					} else if strings.Contains(res, args[0]) {
						s.Logf("Using closest match %q\n", res)
						gvr = r
						break
					}
				}
				if gvr.Resource == "" {
					return nil, fmt.Errorf("%q not a known resource, see 'k8s/resources' for full list", args[0])
				}

				ns, name, found := strings.Cut(args[1], "/")
				if !found {
					name = ns
					ns = ""
				}

				return func(s *script.State) (stdout string, stderr string, err error) {
					var trackerErr error
					for _, tc := range fc.trackers {
						obj, err := tc.tracker.Get(gvr, ns, name)
						if err == nil {
							bs, err := k8sYaml.Marshal(obj)
							if file != "" {
								return "", "", os.WriteFile(s.Path(file), bs, 0644)
							}
							return string(bs), "", err
						}
						trackerErr = errors.Join(trackerErr, err)
					}
					return "", "", fmt.Errorf("%w: no tracker recognized %s", trackerErr, gvr)
				}, nil
			},
		),

		"k8s/list": script.Command(
			script.CmdUsage{
				Summary: "List K8s objects in the object trackers",
				Detail: []string{
					"For example to list pods in any namespace: k8s/list v1.pods ''",
					"Run 'k8s/resources' for a list of seen resources.",
				},
				Args: "resource namespace",
				Flags: func(fs *pflag.FlagSet) {
					fs.StringP("out", "o", "", "File to write to instead of stdout")
				},
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				file, err := s.Flags.GetString("out")
				if err != nil {
					return nil, err
				}
				if len(args) != 2 {
					return nil, fmt.Errorf("%w: expected resource and namespace", script.ErrUsage)
				}

				var gvr schema.GroupVersionResource
				var gvk schema.GroupVersionKind
				for k, r := range seenResources.All() {
					res := showGVR(r)
					if res == args[0] {
						gvr = r
						gvk = k
						break
					} else if strings.Contains(res, args[0]) {
						s.Logf("Using closest match %q\n", res)
						gvr = r
						gvk = k
						break
					}
				}
				if gvr.Resource == "" {
					return nil, fmt.Errorf("%q not a known resource, see 'k8s/resources' for full list", args[0])
				}

				return func(s *script.State) (stdout string, stderr string, err error) {
					var trackerErr error
					for _, tc := range fc.trackers {
						obj, err := tc.tracker.List(gvr, gvk, args[1])
						if err == nil {
							bs, err := k8sYaml.Marshal(obj)
							if file != "" {
								return "", "", os.WriteFile(s.Path(file), bs, 0644)
							}
							return string(bs), "", err
						}
						trackerErr = errors.Join(trackerErr, err)
					}
					return "", "", fmt.Errorf("%w: no tracker recognized %s", trackerErr, gvr)
				}, nil
			},
		),

		"k8s/summary": script.Command(
			script.CmdUsage{
				Summary: "Show a summary of object trackers",
				Args:    "(output file)",
				Detail: []string{
					"Lists each object tracker and the objects stored within",
				},
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				out := s.LogWriter()
				if len(args) == 1 {
					f, err := os.OpenFile(s.Path(args[0]), os.O_CREATE|os.O_WRONLY, 0644)
					if err != nil {
						return nil, err
					}
					defer f.Close()
					out = f
				}
				for _, tc := range fc.trackers {
					fmt.Fprintf(out, "%s:\n", tc.domain)
					for gvk, gvr := range seenResources.All() {
						objs, err := tc.tracker.List(gvr, gvk, "")
						if err == nil {
							lst, _ := meta.ExtractList(objs)
							fmt.Fprintf(out, "- %s: %d\n", showGVR(gvr), len(lst))
						}
					}
				}
				return nil, nil
			},
		),

		"k8s/resources": script.Command(
			script.CmdUsage{
				Summary: "List which resources have been seen by the fake client",
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				return func(s *script.State) (stdout string, stderr string, err error) {
					var buf strings.Builder
					for _, gvr := range seenResources.All() {
						fmt.Fprintf(&buf, "%s\n", showGVR(gvr))
					}
					stdout = buf.String()
					return
				}, nil
			},
		),
	}
}

// overrideTracker changes the internal 'tracker' field in the generated
// clientset to point to our object tracker. This allows using the Tracker()
// method without ending up getting the wrong one.
func overrideTracker(cs prepender, ot k8sTesting.ObjectTracker) {
	type fakeLayout struct {
		k8sTesting.Fake
		discovery uintptr
		tracker   k8sTesting.ObjectTracker
	}

	f := (*fakeLayout)(unsafe.Pointer(reflect.ValueOf(cs).Pointer()))
	f.tracker = ot

	if cs.Tracker() != ot {
		panic("overrideTracker failed, layout changed?")
	}
}
