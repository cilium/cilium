// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"slices"
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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	versionapi "k8s.io/apimachinery/pkg/version"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/discovery"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8sTesting "k8s.io/client-go/testing"
	mcsapi_fake "sigs.k8s.io/mcs-api/pkg/client/clientset/versioned/fake"
	policy_fake "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned/fake"
	k8sYaml "sigs.k8s.io/yaml"

	k8sclient "github.com/cilium/cilium/pkg/k8s/client"
	cilium_fake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	slim_clientset "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned"
	slim_fake "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/k8s/testutils"
)

// We do not create a cell as global variable since
// compiler will compile all of the fake protobufs into the release
// binary which increases the binary size by ~20 MB
var FakeClientCell = func() cell.Cell {
	return cell.Module(
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
}

type (
	MCSAPIFakeClientset     = mcsapi_fake.Clientset
	KubernetesFakeClientset = fake.Clientset
	SlimFakeClientset       = slim_fake.Clientset
	CiliumFakeClientset     = cilium_fake.Clientset
	APIExtFakeClientset     = apiext_fake.Clientset
	PolicyFakeClientset     = policy_fake.Clientset
)

type FakeClientset struct {
	disabled bool

	*MCSAPIFakeClientset
	*KubernetesFakeClientset
	*CiliumFakeClientset
	*APIExtFakeClientset
	*PolicyFakeClientset
	k8sclient.ClientsetGetters

	ot *statedbObjectTracker

	SlimFakeClientset *SlimFakeClientset

	trackers []struct {
		domain  string
		tracker k8sTesting.ObjectTracker
	}
}

var _ k8sclient.Clientset = &FakeClientset{}

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

func (c *FakeClientset) Config() k8sclient.Config {
	return k8sclient.Config{
		ClientParams: k8sclient.ClientParams{},
		SharedConfig: k8sclient.SharedConfig{
			EnableK8s: c.IsEnabled(),
		},
	}
}

func (c *FakeClientset) RestConfig() *rest.Config {
	return &rest.Config{}
}

func NewFakeClientset(log *slog.Logger) (*FakeClientset, k8sclient.Clientset) {
	return NewFakeClientsetWithTracker(log, nil)
}

func NewFakeClientsetWithTracker(log *slog.Logger, ot *statedbObjectTracker) (*FakeClientset, k8sclient.Clientset) {
	version := testutils.DefaultVersion
	return NewFakeClientsetWithVersion(log, ot, version)
}

func NewFakeClientsetWithVersion(log *slog.Logger, ot *statedbObjectTracker, version string) (*FakeClientset, k8sclient.Clientset) {
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
		PolicyFakeClientset:     policy_fake.NewSimpleClientset(),
		KubernetesFakeClientset: fake.NewSimpleClientset(),
	}
	client.KubernetesFakeClientset.Resources = resources
	client.SlimFakeClientset.Resources = resources
	client.CiliumFakeClientset.Resources = resources
	client.APIExtFakeClientset.Resources = resources
	client.MCSAPIFakeClientset.Resources = resources
	client.PolicyFakeClientset.Resources = resources
	client.ot = ot

	otx := ot.For("*", testutils.Scheme, testutils.Decoder())
	prependReactors(client.SlimFakeClientset, otx)
	prependReactors(client.CiliumFakeClientset, otx)
	prependReactors(client.MCSAPIFakeClientset, otx)
	prependReactors(client.PolicyFakeClientset, otx)
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

	client.ClientsetGetters = k8sclient.ClientsetGetters{Clientset: &client}
	return &client, &client
}

// See a comment for FakeClientCell
var FakeClientBuilderCell = func() cell.Cell {
	return cell.Group(
		cell.ProvidePrivate(newStateDBObjectTracker),
		cell.Provide(FakeClientBuilder),
	)
}

func FakeClientBuilder(log *slog.Logger, ot *statedbObjectTracker) k8sclient.ClientBuilderFunc {
	fc, _ := NewFakeClientsetWithTracker(log, ot)
	return func(_ string) (k8sclient.Clientset, error) {
		return fc, nil
	}
}

func toVersionInfo(rawVersion string) *versionapi.Info {
	parts := strings.Split(rawVersion, ".")
	return &versionapi.Info{Major: parts[0], Minor: parts[1]}
}

type prepender interface {
	PrependReactor(verb string, resource string, reaction k8sTesting.ReactionFunc)
	PrependWatchReactor(resource string, reaction k8sTesting.WatchReactionFunc)
	Tracker() k8sTesting.ObjectTracker
}

func prependReactors(cs prepender, ot k8sTesting.ObjectTracker) {
	cs.PrependReactor("*", "*", k8sTesting.ObjectReaction(ot))
	cs.PrependWatchReactor("*", watchReactorFunc(ot))

	// Switch out the tracker to our version.
	overrideTracker(cs, ot)
}

func watchReactorFunc(ot k8sTesting.ObjectTracker) k8sTesting.WatchReactionFunc {
	return func(action k8sTesting.Action) (handled bool, ret watch.Interface, err error) {
		var opts metav1.ListOptions
		if watchAction, ok := action.(k8sTesting.WatchActionImpl); ok {
			opts = watchAction.ListOptions
		}
		gvr := action.GetResource()
		ns := action.GetNamespace()
		watch, err := ot.Watch(gvr, ns, opts)
		return true, watch, err
	}
}

func showGVR(gvr schema.GroupVersionResource) string {
	if gvr.Group == "" {
		return fmt.Sprintf("%s.%s", gvr.Version, gvr.Resource)
	}
	return fmt.Sprintf("%s.%s.%s", gvr.Group, gvr.Version, gvr.Resource)
}

func resolveGVR(resource string, gvrks []gvrk) (schema.GroupVersionResource, schema.GroupVersionKind, string, bool) {
	for _, gvrk := range gvrks {
		res := showGVR(gvrk.GroupVersionResource)
		if res == resource {
			return gvrk.GroupVersionResource, gvrk.groupVersionKind(), "", true
		}
		if strings.Contains(res, resource) {
			return gvrk.GroupVersionResource, gvrk.groupVersionKind(), res, true
		}
	}
	return schema.GroupVersionResource{}, schema.GroupVersionKind{}, "", false
}

func FakeClientCommands(fc *FakeClientset) map[string]script.Cmd {
	readInputFile := func(s *script.State, file string) ([]byte, error) {
		b, err := os.ReadFile(s.Path(file))
		if err == nil {
			return b, nil
		}
		// Try relative to current directory, e.g. to allow reading "testdata/foo.yaml"
		b, err = os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", file, err)
		}
		return b, nil
	}

	decodeTrackerObjects := func(s *script.State, file string) ([]object, schema.GroupVersionResource, error) {
		b, err := readInputFile(s, file)
		if err != nil {
			return nil, schema.GroupVersionResource{}, err
		}

		obj, gvk, err := testutils.DecodeObjectGVK(b)
		if err != nil {
			return nil, schema.GroupVersionResource{}, fmt.Errorf("decode: %w", err)
		}
		kobj, _, _ := testutils.DecodeKubernetesObject(b)
		gvr, _ := meta.UnsafeGuessKindToResource(*gvk)

		toObject := func(domain string, obj runtime.Object) (object, error) {
			objMeta, err := meta.Accessor(obj)
			if err != nil {
				return object{}, fmt.Errorf("accessor: %w", err)
			}
			return object{
				objectId: newObjectId(domain, gvr, objMeta.GetNamespace(), objMeta.GetName()),
				kind:     gvk.Kind,
				o:        obj,
			}, nil
		}

		objs := make([]object, 0, 2)
		o, err := toObject("*", obj)
		if err != nil {
			return nil, schema.GroupVersionResource{}, err
		}
		objs = append(objs, o)

		if kobj != nil {
			o, err := toObject("k8s", kobj)
			if err != nil {
				return nil, schema.GroupVersionResource{}, err
			}
			objs = append(objs, o)
		}

		return objs, gvr, nil
	}

	addUpdateOrDelete := func(s *script.State, action string, files []string) error {
		for _, file := range files {
			b, err := readInputFile(s, file)
			if err != nil {
				return err
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
					strict, _ := s.Flags.GetBool("strict")
					if strict {
						trackerErr = tc.tracker.Update(gvr, o, ns)
					} else {
						// Patch does not check for conflicts.
						trackerErr = tc.tracker.Patch(gvr, o, ns)
					}

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
				Flags: func(fs *pflag.FlagSet) {
					fs.Bool("strict", false,
						"Enable strict optimistic concurrency control")
				},
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
					fs.StringSlice("show-redacted", nil, "Redacted fields to show (supported: resource-version, uid)")
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

				gvrks := slices.Collect(fc.ot.getGVRKs())
				gvr, _, match, ok := resolveGVR(args[0], gvrks)
				if !ok {
					return nil, fmt.Errorf("%q not a known resource, see 'k8s/resources' for full list", args[0])
				}
				if match != "" {
					s.Logf("Using closest match %q\n", match)
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
							if err := redact(obj, s.Flags); err != nil {
								return "", "", fmt.Errorf("redacting fields: %w", err)
							}

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
					fs.StringSlice("show-redacted", nil, "Redacted fields to show (supported: resource-version, uid)")
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

				gvrks := slices.Collect(fc.ot.getGVRKs())
				gvr, gvk, match, ok := resolveGVR(args[0], gvrks)
				if !ok {
					return nil, fmt.Errorf("%q not a known resource, see 'k8s/resources' for full list", args[0])
				}
				if match != "" {
					s.Logf("Using closest match %q\n", match)
				}

				return func(s *script.State) (stdout string, stderr string, err error) {
					var trackerErr error
					for _, tc := range fc.trackers {
						obj, err := tc.tracker.List(gvr, gvk, args[1])
						if err == nil {
							if err := redact(obj, s.Flags); err != nil {
								return "", "", fmt.Errorf("redacting fields: %w", err)
							}

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

		"k8s/resync": script.Command(
			script.CmdUsage{
				Summary: "Atomically replace tracked objects for a resource and restart watches",
				Detail: []string{
					"This closes matching watch streams, deletes the existing tracked",
					"objects for the resource, and inserts the optional new objects.",
				},
				Args: "resource (files...)",
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) == 0 {
					return nil, fmt.Errorf("%w: expected resource and optional files", script.ErrUsage)
				}

				gvrks := slices.Collect(fc.ot.getGVRKs())
				gvr, _, match, ok := resolveGVR(args[0], gvrks)
				if !ok {
					return nil, fmt.Errorf("%q not a known resource, see 'k8s/resources' for full list", args[0])
				}
				if match != "" {
					s.Logf("Using closest match %q\n", match)
				}

				files := args[1:]

				replacements := make([]object, 0, len(files)*2)
				for _, file := range files {
					objs, fileGVR, err := decodeTrackerObjects(s, file)
					if err != nil {
						return nil, err
					}
					if fileGVR != gvr {
						return nil, fmt.Errorf("%s is %s, expected %s", file, showGVR(fileGVR), showGVR(gvr))
					}
					replacements = append(replacements, objs...)
				}

				return nil, func() error {
					stopped, rev, err := fc.ot.Resync(gvr, replacements)
					if err != nil {
						return err
					}
					s.Logf(
						"Restarted %d watch(es) for %s at revision %d with %d replacement object(s)\n",
						stopped, showGVR(gvr), rev, len(replacements),
					)
					return nil
				}()
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
					for gvrk := range fc.ot.getGVRKs() {
						objs, err := tc.tracker.List(gvrk.GroupVersionResource, gvrk.groupVersionKind(), "")
						if err == nil {
							lst, _ := meta.ExtractList(objs)
							fmt.Fprintf(out, "- %s: %d\n", showGVR(gvrk.GroupVersionResource), len(lst))
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
					for gvrk := range fc.ot.getGVRKs() {
						fmt.Fprintf(&buf, "%s\n", showGVR(gvrk.GroupVersionResource))
					}
					stdout = buf.String()
					return
				}, nil
			},
		),
	}
}

// redact redacts the UID and resource version fields, to make the output more deterministic.
func redact(obj runtime.Object, flags *pflag.FlagSet) error {
	show, err := flags.GetStringSlice("show-redacted")
	if err != nil {
		return err
	}

	redactObj := func(obj runtime.Object) error {
		meta, err := meta.Accessor(obj)
		if err != nil {
			return err
		}

		if !slices.Contains(show, "resource-version") {
			meta.SetResourceVersion("")
		}

		if !slices.Contains(show, "uid") {
			meta.SetUID("")
		}

		return nil
	}

	list, err := meta.ListAccessor(obj)
	if err != nil {
		return redactObj(obj)
	}

	if !slices.Contains(show, "resource-version") {
		list.SetResourceVersion("")
	}

	return meta.EachListItem(obj, redactObj)
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
