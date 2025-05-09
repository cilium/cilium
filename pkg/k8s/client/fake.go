// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"
	apiext_fake "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/discovery"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8sTesting "k8s.io/client-go/testing"
	mcsapi_fake "sigs.k8s.io/mcs-api/pkg/client/clientset/versioned/fake"
	k8sYaml "sigs.k8s.io/yaml"

	cilium_fake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	slim_clientset "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned"
	slim_fake "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var FakeClientCell = cell.Module(
	"k8s-fake-client",
	"Fake Kubernetes client",

	cell.Provide(
		NewFakeClientset,
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

	trackers map[string]k8sTesting.ObjectTracker

	watchers lock.Map[string, struct{}]
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
	version := testutils.DefaultVersion
	return NewFakeClientsetWithVersion(log, version)
}

// trackerPreference has the trackers in preference order,
// e.g. which tracker to look into first for k8s/get or k8s/list.
// We prefer the slim one over the kubernetes one as that's the one
// likely used in Cilium.
var trackerPreference = []string{
	"slim",
	"cilium",
	"mcs",
	"apiext",
	"kubernetes",
}

func NewFakeClientsetWithVersion(log *slog.Logger, version string) (*FakeClientset, Clientset) {
	if version == "" {
		version = testutils.DefaultVersion
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
	client.trackers = map[string]k8sTesting.ObjectTracker{
		"slim":       augmentTracker(log, client.SlimFakeClientset, &client.watchers),
		"cilium":     augmentTracker(log, client.CiliumFakeClientset, &client.watchers),
		"mcs":        augmentTracker(log, client.MCSAPIFakeClientset, &client.watchers),
		"kubernetes": augmentTracker(log, client.KubernetesFakeClientset, &client.watchers),
		"apiext":     augmentTracker(log, client.APIExtFakeClientset, &client.watchers),
	}

	fd := client.KubernetesFakeClientset.Discovery().(*fakediscovery.FakeDiscovery)
	fd.FakedServerVersion = toVersionInfo(version)

	client.clientsetGetters = clientsetGetters{&client}
	return &client, &client
}

var FakeClientBuilderCell = cell.Provide(FakeClientBuilder)

func FakeClientBuilder(log *slog.Logger) ClientBuilderFunc {
	fc, _ := NewFakeClientset(log)
	return func(_ string) (Clientset, error) {
		return fc, nil
	}
}

func showGVR(gvr schema.GroupVersionResource) string {
	if gvr.Group == "" {
		return fmt.Sprintf("%s.%s", gvr.Version, gvr.Resource)
	}
	return fmt.Sprintf("%s.%s.%s", gvr.Group, gvr.Version, gvr.Resource)
}

func FakeClientCommands(fc *FakeClientset) map[string]script.Cmd {
	seenResources := map[schema.GroupVersionKind]schema.GroupVersionResource{}

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
			gvr, _ := meta.UnsafeGuessKindToResource(*gvk)
			objMeta, err := meta.Accessor(obj)
			if err != nil {
				return fmt.Errorf("accessor: %w", err)
			}
			seenResources[*gvk] = gvr

			name := objMeta.GetName()
			ns := objMeta.GetNamespace()

			// Try to add the object to all the trackers. If one of them
			// accepts we're good. We'll add to all since multiple trackers
			// may accept (e.g. slim and kubernetes).

			// err will get set to nil if any of the tracker methods succeed.
			// start with a non-nil default error.
			err = fmt.Errorf("none of the trackers of FakeClientset accepted %T", obj)
			for trackerName, tracker := range fc.trackers {
				var trackerErr error
				switch action {
				case "add":
					trackerErr = tracker.Add(obj)
				case "update":
					trackerErr = tracker.Update(gvr, obj, ns)
				case "delete":
					trackerErr = tracker.Delete(gvr, ns, name)
				}
				if err != nil {
					if trackerErr == nil {
						// One of the trackers accepted the object, it's a success!
						err = nil
					} else {
						err = errors.Join(err, fmt.Errorf("%s: %w", trackerName, trackerErr))
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
				for _, r := range seenResources {
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
					for _, trackerName := range trackerPreference {
						tracker := fc.trackers[trackerName]
						obj, err := tracker.Get(gvr, ns, name)
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
				for k, r := range seenResources {
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
					for _, trackerName := range trackerPreference {
						tracker := fc.trackers[trackerName]
						obj, err := tracker.List(gvr, gvk, args[1])
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
				Detail: []string{
					"Lists each object tracker and the objects stored within.",
				},
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				for _, trackerName := range trackerPreference {
					tracker := fc.trackers[trackerName]
					s.Logf("%s:\n", trackerName)
					for gvk, gvr := range seenResources {
						objs, err := tracker.List(gvr, gvk, "")
						if err == nil {
							lst, _ := meta.ExtractList(objs)
							s.Logf("- %s: %d\n", showGVR(gvr), len(lst))
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
					for _, gvr := range seenResources {
						fmt.Fprintf(&buf, "%s\n", showGVR(gvr))
					}
					stdout = buf.String()
					return
				}, nil
			},
		),

		"k8s/wait-watchers": script.Command(
			script.CmdUsage{
				Summary: "Wait for watchers for given resources to appear",
				Detail: []string{
					"Takes a list of resources and waits for a Watch() to appear for it.",
					"",
					"Useful when working with an informer/reflector that is not backed by",
					"a StateDB table and thus cannot use 'db/initialized'.",
				},
				Args: "resources...",
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				resources := map[string]struct{}{}
				for _, r := range args {
					resources[r] = struct{}{}
				}
				for s.Context().Err() == nil && len(resources) > 0 {
					for r := range resources {
						_, ok := fc.watchers.Load(r)
						if ok {
							delete(resources, r)
						}
					}
					time.Sleep(10 * time.Millisecond)
				}
				if len(resources) > 0 {
					seen := []string{}
					fc.watchers.Range(func(key string, value struct{}) bool {
						seen = append(seen, key)
						return true
					})
					return nil, fmt.Errorf("watchers did not appear. saw: %v", seen)
				}
				return nil, nil
			},
		),
	}

}

type fakeWithTracker interface {
	PrependReactor(verb string, resource string, reaction k8sTesting.ReactionFunc)
	PrependWatchReactor(resource string, reaction k8sTesting.WatchReactionFunc)
	Tracker() k8sTesting.ObjectTracker
}

// augmentTracker augments the fake clientset to record watchers.
// The reason we need to do this is the following: The k8s object tracker's implementation
// of Watch is not equivalent to Watch on a real api-server, as it does not respect the
// ResourceVersion from whence to start the watch. As a consequence, when informers (or
// reflectors) call ListAndWatch, they miss events which occur between the end of List and
// the establishment of Watch.
func augmentTracker[T fakeWithTracker](log *slog.Logger, f T, watchers *lock.Map[string, struct{}]) k8sTesting.ObjectTracker {
	o := f.Tracker()

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
			watchName := showGVR(gvr)
			if _, ok := watchers.Load(watchName); ok {
				log.Warn("Multiple watches for resource intercepted. This highlights a potential cause for flakes", logfields.Resource, watchName)
			}

			log.Debug("Watch started", logfields.Resource, watchName)
			watchers.Store(watchName, struct{}{})

			return true, watch, nil
		})

	return o
}
