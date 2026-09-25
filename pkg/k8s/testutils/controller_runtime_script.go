// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/cilium/hive/script"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/yaml"
)

// ControllerRuntimeScriptCommands provides fixture CRUD and explicit reconciliation
// against one controller-runtime client. The caller registers named reconcilers.
// Writes and reads retain the client's metadata and update semantics.
func ControllerRuntimeScriptCommands(
	c client.Client,
	reconcilers map[string]reconcile.Reconciler,
) map[string]script.Cmd {
	readObject := func(s *script.State, file string) (client.Object, error) {
		data, err := os.ReadFile(s.Path(file))
		if err != nil {
			return nil, err
		}
		obj, _, err := serializer.NewCodecFactory(c.Scheme(), serializer.EnableStrict).UniversalDeserializer().Decode(data, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("decode %s: %w", file, err)
		}
		object, ok := obj.(client.Object)
		if !ok {
			return nil, fmt.Errorf("%s is not a Kubernetes object: %T", file, obj)
		}
		return object, nil
	}

	modify := func(operation string, action func(*script.State, client.Object) error) script.Cmd {
		return script.Command(script.CmdUsage{
			Summary: operation + " Kubernetes objects via controller-runtime",
			Args:    "files...",
		}, func(s *script.State, files ...string) (script.WaitFunc, error) {
			if len(files) == 0 {
				return nil, script.ErrUsage
			}
			for _, file := range files {
				obj, err := readObject(s, file)
				if err != nil {
					return nil, err
				}
				if err := action(s, obj); err != nil {
					return nil, err
				}
			}
			return nil, nil
		})
	}

	return map[string]script.Cmd{
		"k8s/ctrl-runtime/add": modify("Add", func(s *script.State, obj client.Object) error {
			return c.Create(s.Context(), obj)
		}),
		"k8s/ctrl-runtime/update": modify("Update", func(s *script.State, obj client.Object) error {
			return c.Update(s.Context(), obj)
		}),
		"k8s/ctrl-runtime/status": modify("Update status of", func(s *script.State, obj client.Object) error {
			return c.Status().Update(s.Context(), obj)
		}),
		"k8s/ctrl-runtime/delete": modify("Delete", func(s *script.State, obj client.Object) error {
			return c.Delete(s.Context(), obj)
		}),
		"k8s/ctrl-runtime/get": script.Command(script.CmdUsage{
			Summary: "Get a Kubernetes object via controller-runtime",
			Args:    "resource namespace/name",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP("out", "o", "", "File to write to instead of stdout")
			},
		}, func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, script.ErrUsage
			}
			object, err := newObjectForResource(c.Scheme(), args[0])
			if err != nil {
				return nil, err
			}
			gvk := object.GetObjectKind().GroupVersionKind()
			key, err := scriptObjectKey(args[1])
			if err != nil {
				return nil, err
			}
			file, err := s.Flags.GetString("out")
			if err != nil {
				return nil, err
			}
			return func(s *script.State) (string, string, error) {
				if err := c.Get(s.Context(), key, object); err != nil {
					return "", "", err
				}
				object.GetObjectKind().SetGroupVersionKind(gvk)
				data, err := yaml.Marshal(object)
				if err != nil {
					return "", "", err
				}
				if file != "" {
					return "", "", os.WriteFile(s.Path(file), data, 0644)
				}
				return string(data), "", nil
			}, nil
		}),
		"k8s/ctrl-runtime/reconcile": script.Command(script.CmdUsage{
			Summary: "Run a controller-runtime reconciler",
			Args:    "controller namespace/name",
		}, func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, script.ErrUsage
			}
			r, ok := reconcilers[args[0]]
			if !ok {
				return nil, fmt.Errorf("unknown controller %q", args[0])
			}
			key, err := scriptObjectKey(args[1])
			if err != nil {
				return nil, err
			}
			result, err := r.Reconcile(s.Context(), ctrl.Request{NamespacedName: key})
			if err != nil {
				return nil, err
			}
			if !result.IsZero() {
				return nil, fmt.Errorf("reconcile returned non-zero result: %v", result)
			}
			return nil, nil
		}),
		"k8s/ctrl-runtime/diff": script.Command(script.CmdUsage{
			Summary: "Diff Kubernetes objects, ignoring volatile metadata",
			Args:    "actual expected",
		}, func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, script.ErrUsage
			}
			return func(s *script.State) (string, string, error) {
				expected, err := readObject(s, args[1])
				if err != nil {
					return "", "", err
				}
				data, err := os.ReadFile(s.Path(args[0]))
				if err != nil {
					return "", "", err
				}
				actual := reflect.New(reflect.TypeOf(expected).Elem()).Interface().(client.Object)
				if err := yaml.UnmarshalStrict(data, actual); err != nil {
					return "", "", fmt.Errorf("decode %s: %w", args[0], err)
				}
				if diff := cmp.Diff(actual, expected,
					cmpopts.IgnoreFields(metav1.TypeMeta{}, "Kind", "APIVersion"),
					cmpopts.IgnoreFields(metav1.ObjectMeta{}, "ResourceVersion"),
					cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime"),
				); diff != "" {
					return "", "", fmt.Errorf("%s and %s differ (-actual +expected):\n%s", args[0], args[1], diff)
				}
				return "", "", nil
			}, nil
		}),
	}
}

// newObjectForResource finds a typed object in the scheme by resource name.
// Version-qualified names can select non-preferred versions.
func newObjectForResource(scheme *runtime.Scheme, resource string) (client.Object, error) {
	var found client.Object
	for gvk := range scheme.AllKnownTypes() {
		if gvk.Version == runtime.APIVersionInternal {
			continue
		}
		gvr, _ := meta.UnsafeGuessKindToResource(gvk)
		qualified := gvr.Version + "." + gvr.Resource
		if gvr.Group != "" {
			qualified = gvr.Group + "." + qualified
		}
		if resource != qualified {
			versions := scheme.PrioritizedVersionsForGroup(gvk.Group)
			if resource != gvr.Resource || len(versions) == 0 || versions[0].Version != gvk.Version {
				continue
			}
		}
		obj, err := scheme.New(gvk)
		if err != nil {
			return nil, err
		}
		object, ok := obj.(client.Object)
		if !ok {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("ambiguous resource %q (use a group.version.resource name)", resource)
		}
		object.GetObjectKind().SetGroupVersionKind(gvk)
		found = object
	}
	if found == nil {
		return nil, fmt.Errorf("unknown resource %q", resource)
	}
	return found, nil
}

func scriptObjectKey(raw string) (client.ObjectKey, error) {
	namespace, name, ok := strings.Cut(raw, "/")
	if !ok {
		name = namespace
		namespace = ""
	}
	if name == "" || strings.Contains(name, "/") {
		return client.ObjectKey{}, fmt.Errorf("invalid namespaced name %q", raw)
	}
	return client.ObjectKey{Namespace: namespace, Name: name}, nil
}
