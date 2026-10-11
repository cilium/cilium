// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"
	k8syaml "sigs.k8s.io/yaml"
)

// ToYAML marshals an object to YAML.
func ToYAML(t testing.TB, obj any) string {
	t.Helper()

	data, err := k8syaml.Marshal(obj)
	require.NoError(t, err)

	return strings.TrimSpace(string(data))
}

// ReadYAML unmarshals a YAML fixture into obj.
func ReadYAML(t testing.TB, path string, obj any) {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotEmpty(t, strings.TrimSpace(string(data)), "YAML fixture %s is empty", path)
	require.NoError(t, k8syaml.UnmarshalStrict(data, obj))
}

// ReadObjectsDir reads all YAML documents in a directory using the provided scheme.
func ReadObjectsDir(t testing.TB, dir string, scheme *runtime.Scheme) []client.Object {
	t.Helper()

	files, err := os.ReadDir(dir)
	require.NoError(t, err)

	var objects []client.Object
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		currObjects, err := readObjectsFile(filepath.Join(dir, file.Name()), scheme)
		require.NoError(t, err)
		objects = append(objects, currObjects...)
	}
	return objects
}

func readObjectsFile(path string, scheme *runtime.Scheme) ([]client.Object, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	decoder := serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDeserializer()
	yamlDecoder := yaml.NewYAMLOrJSONDecoder(f, 4096)
	var objects []client.Object
	for {
		var raw json.RawMessage
		err := yamlDecoder.Decode(&raw)
		if errors.Is(err, io.EOF) {
			return objects, nil
		}
		if err != nil {
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		if len(raw) == 0 {
			continue
		}

		obj, _, err := decoder.Decode(raw, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		object, ok := obj.(client.Object)
		if !ok {
			return nil, fmt.Errorf("decode %s: expected Kubernetes object, got %T", path, obj)
		}
		objects = append(objects, object)
	}
}
