/*
Copyright 2022 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package decoder

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
)

// Options are a set of configurations used to instruct the decoding process and otherwise
// alter the output of decoding operations.
type Options struct {
	DefaultGVK  *schema.GroupVersionKind
	MutateFuncs []MutateFunc
}

// DecodeOption is a function that alters the configuration Options used to decode and optionally mutate objects via MutateFuncs
type DecodeOption func(*Options)

// MutateFunc is a function executed after an object is decoded to alter its state in a pre-defined way, and can be used to apply defaults.
// Returning an error halts decoding of any further objects.
type MutateFunc func(obj k8s.Object) error

// HandlerFunc is a function executed after an object has been decoded and patched. If an error is returned, further decoding is halted.
type HandlerFunc func(ctx context.Context, obj k8s.Object) error

// DecodeEachFile resolves files at the filesystem matching the pattern, decoding JSON or YAML files. Supports multi-document files.
//
// If handlerFn returns an error, decoding is halted.
// Options may be provided to configure the behavior of the decoder.
func DecodeEachFile(ctx context.Context, fsys fs.FS, pattern string, handlerFn HandlerFunc, options ...DecodeOption) error {
	files, err := fs.Glob(fsys, pattern)
	if err != nil {
		return err
	}
	for _, file := range files {
		f, err := fsys.Open(file)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := DecodeEach(ctx, f, handlerFn, options...); err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}

// DecodeAllFiles  resolves files at the filesystem matching the pattern, decoding JSON or YAML files. Supports multi-document files.
// Falls back to the unstructured.Unstructured type if a matching type cannot be found for the Kind.
// Options may be provided to configure the behavior of the decoder.
func DecodeAllFiles(ctx context.Context, fsys fs.FS, pattern string, options ...DecodeOption) ([]k8s.Object, error) {
	objects := []k8s.Object{}
	err := DecodeEachFile(ctx, fsys, pattern, func(ctx context.Context, obj k8s.Object) error {
		objects = append(objects, obj)
		return nil
	}, options...)
	return objects, err
}

// ApplyWithManifestDir resolves all the files in the Directory dirPath against the globbing pattern and creates a kubernetes
// resource for each of the resources found under the manifest directory.
func ApplyWithManifestDir(ctx context.Context, r *resources.Resources, dirPath, pattern string, createOptions []resources.CreateOption, options ...DecodeOption) error {
	err := DecodeEachFile(ctx, os.DirFS(dirPath), pattern, CreateHandler(r, createOptions...), options...)
	return err
}

// DeleteWithManifestDir does the reverse of ApplyUsingManifestDir does. This will resolve all files in the dirPath against the pattern and then
// delete those kubernetes resources found under the manifest directory.
func DeleteWithManifestDir(ctx context.Context, r *resources.Resources, dirPath, pattern string, deleteOptions []resources.DeleteOption, options ...DecodeOption) error {
	err := DecodeEachFile(ctx, os.DirFS(dirPath), pattern, DeleteHandler(r, deleteOptions...), options...)
	return err
}

// Decode a stream of documents of any Kind using either the innate typing of the scheme.
// Falls back to the unstructured.Unstructured type if a matching type cannot be found for the Kind.
//
// If handlerFn returns an error, decoding is halted.
// Options may be provided to configure the behavior of the decoder.
func DecodeEach(ctx context.Context, manifest io.Reader, handlerFn HandlerFunc, options ...DecodeOption) error {
	decoder := yaml.NewYAMLReader(bufio.NewReader(manifest))
	for {
		b, err := decoder.Read()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return err
		}
		obj, err := DecodeAny(bytes.NewReader(b), options...)
		if err != nil {
			return err
		}
		if err := handlerFn(ctx, obj); err != nil {
			return err
		}
	}
	return nil
}

// DecodeAll is a stream of  documents of any Kind using either the innate typing of the scheme.
// Falls back to the unstructured.Unstructured type if a matching type cannot be found for the Kind.
// Options may be provided to configure the behavior of the decoder.
func DecodeAll(ctx context.Context, manifest io.Reader, options ...DecodeOption) ([]k8s.Object, error) {
	objects := []k8s.Object{}
	err := DecodeEach(ctx, manifest, func(ctx context.Context, obj k8s.Object) error {
		objects = append(objects, obj)
		return nil
	}, options...)
	return objects, err
}

// DecodeAny decodes any single-document YAML or JSON input using either the innate typing of the scheme.
// Falls back to the unstructured.Unstructured type if a matching type cannot be found for the Kind.
// Options may be provided to configure the behavior of the decoder.
func DecodeAny(manifest io.Reader, options ...DecodeOption) (k8s.Object, error) {
	decodeOpt := &Options{}
	for _, opt := range options {
		opt(decodeOpt)
	}

	k8sDecoder := serializer.NewCodecFactory(scheme.Scheme).UniversalDeserializer().Decode
	b, err := io.ReadAll(manifest)
	if err != nil {
		return nil, err
	}
	runtimeObj, _, err := k8sDecoder(b, decodeOpt.DefaultGVK, nil)
	if runtime.IsNotRegisteredError(err) {
		// fallback to the unstructured.Unstructured type if a type is not registered for the Object to be decoded
		runtimeObj = &unstructured.Unstructured{}
		if err := yaml.Unmarshal(b, runtimeObj); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	obj, ok := runtimeObj.(k8s.Object)
	if !ok {
		return nil, err
	}
	for _, patch := range decodeOpt.MutateFuncs {
		if err := patch(obj); err != nil {
			return nil, err
		}
	}
	return obj, nil
}

// Decode a single-document YAML or JSON file into the provided object. Patches are applied
// after decoding to the object to update the loaded resource.
func Decode(manifest io.Reader, obj k8s.Object, options ...DecodeOption) error {
	decodeOpt := &Options{}
	for _, opt := range options {
		opt(decodeOpt)
	}
	if err := yaml.NewYAMLOrJSONDecoder(manifest, 1024).Decode(obj); err != nil {
		return err
	}
	for _, patch := range decodeOpt.MutateFuncs {
		if err := patch(obj); err != nil {
			return err
		}
	}
	return nil
}

// DecodeFile decodes a single-document YAML or JSON file into the provided object. Patches are applied
// after decoding to the object to update the loaded resource.
func DecodeFile(fsys fs.FS, manifestPath string, obj k8s.Object, options ...DecodeOption) error {
	f, err := fsys.Open(manifestPath)
	if err != nil {
		return err
	}
	defer f.Close()
	return Decode(f, obj, options...)
}

// DecodeString decodes a single-document YAML or JSON string into the provided object. Patches are applied
// after decoding to the object to update the loaded resource.
func DecodeString(rawManifest string, obj k8s.Object, options ...DecodeOption) error {
	return Decode(strings.NewReader(rawManifest), obj, options...)
}

// DefaultGVK instructs the decoder to use the given type to look up the appropriate Go type to decode into
// instead of its default behavior of deciding this by decoding the Group, Version, and Kind fields.
func DefaultGVK(defaults *schema.GroupVersionKind) DecodeOption {
	return func(do *Options) {
		do.DefaultGVK = defaults
	}
}

// MutateOption can be used to add a custom MutateFunc to the DecodeOption
// used to configure the decoding of objects
func MutateOption(m MutateFunc) DecodeOption {
	return func(do *Options) {
		do.MutateFuncs = append(do.MutateFuncs, m)
	}
}

// MutateLabels is an optional parameter to decoding functions that will patch an objects metadata.labels
func MutateLabels(overrides map[string]string) DecodeOption {
	return MutateOption(func(obj k8s.Object) error {
		labels := obj.GetLabels()
		if labels == nil {
			labels = make(map[string]string)
			obj.SetLabels(labels)
		}
		for key, value := range overrides {
			labels[key] = value
		}
		return nil
	})
}

// MutateAnnotations is an optional parameter to decoding functions that will patch an objects metadata.annotations
func MutateAnnotations(overrides map[string]string) DecodeOption {
	return MutateOption(func(obj k8s.Object) error {
		annotations := obj.GetAnnotations()
		if annotations == nil {
			annotations = make(map[string]string)
			obj.SetLabels(annotations)
		}
		for key, value := range overrides {
			annotations[key] = value
		}
		return nil
	})
}

// MutateOwnerAnnotations is an optional parameter to decoding functions that will patch objects using the given owner object
func MutateOwnerAnnotations(owner k8s.Object) DecodeOption {
	return MutateOption(func(obj k8s.Object) error {
		return controllerutil.SetOwnerReference(owner, obj, scheme.Scheme)
	})
}

// MutateNamespace is an optional parameter to decoding functions that will patch objects with the given namespace name
func MutateNamespace(namespace string) DecodeOption {
	return MutateOption(func(obj k8s.Object) error {
		obj.SetNamespace(namespace)
		return nil
	})
}

// CreateHandler returns a HandlerFunc that will create objects
func CreateHandler(r *resources.Resources, opts ...resources.CreateOption) HandlerFunc {
	return func(ctx context.Context, obj k8s.Object) error {
		return r.Create(ctx, obj, opts...)
	}
}

// ReadHandler returns a HandlerFunc that will use the provided object's Kind / Namespace / Name to retrieve
// the current state of the object using the provided Resource client.
// This helper makes it easy to use a stale reference to an object to retrieve its current version.
func ReadHandler(r *resources.Resources, handler HandlerFunc) HandlerFunc {
	return func(ctx context.Context, obj k8s.Object) error {
		name := obj.GetName()
		namespace := obj.GetNamespace()
		// use scheme.Scheme to generate a new, empty object to use as a base for decoding into
		gvk := obj.GetObjectKind().GroupVersionKind()
		o, err := scheme.Scheme.New(gvk)
		if err != nil {
			return fmt.Errorf("resources: GroupVersionKind not found in scheme: %s", gvk.String())
		}
		obj, ok := o.(k8s.Object)
		if !ok {
			return fmt.Errorf("resources: unexpected type %T does not satisfy k8s.Object", obj)
		}
		if err := r.Get(ctx, name, namespace, obj); err != nil {
			return err
		}
		return handler(ctx, obj)
	}
}

// UpdateHandler returns a HandlerFunc that will update objects
func UpdateHandler(r *resources.Resources, opts ...resources.UpdateOption) HandlerFunc {
	return func(ctx context.Context, obj k8s.Object) error {
		return r.Update(ctx, obj, opts...)
	}
}

// DeleteHandler returns a HandlerFunc that will delete objects
func DeleteHandler(r *resources.Resources, opts ...resources.DeleteOption) HandlerFunc {
	return func(ctx context.Context, obj k8s.Object) error {
		return r.Delete(ctx, obj, opts...)
	}
}

// IgnoreErrorHandler returns a HandlerFunc that will ignore the provided error if the errorMatcher returns true
func IgnoreErrorHandler(handler HandlerFunc, errorMatcher func(err error) bool) HandlerFunc {
	return func(ctx context.Context, obj k8s.Object) error {
		if err := handler(ctx, obj); err != nil && !errorMatcher(err) {
			return err
		}
		return nil
	}
}

// NoopHandler returns a Handler func that only returns nil
func NoopHandler(r *resources.Resources, opts ...resources.DeleteOption) HandlerFunc {
	return func(ctx context.Context, obj k8s.Object) error {
		return nil
	}
}

// CreateIgnoreAlreadyExists returns a HandlerFunc that will create objects if they do not already exist
func CreateIgnoreAlreadyExists(r *resources.Resources, opts ...resources.CreateOption) HandlerFunc {
	return IgnoreErrorHandler(CreateHandler(r, opts...), apierrors.IsAlreadyExists)
}

// DeleteIgnoreNotFound returns a HandlerFunc that will delete objects if they do not already exist
func DeleteIgnoreNotFound(r *resources.Resources, opts ...resources.CreateOption) HandlerFunc {
	return IgnoreErrorHandler(CreateHandler(r, opts...), apierrors.IsNotFound)
}
