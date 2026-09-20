// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"encoding/json"
	"errors"
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

	decoder := serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDeserializer()
	var objects []client.Object
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		f, err := os.Open(filepath.Join(dir, file.Name()))
		require.NoError(t, err)
		yamlDecoder := yaml.NewYAMLOrJSONDecoder(f, 4096)

		for {
			var raw json.RawMessage
			err := yamlDecoder.Decode(&raw)
			if errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err, "decode %s", file.Name())
			if len(raw) == 0 {
				continue
			}

			obj, _, err := decoder.Decode(raw, nil, nil)
			require.NoError(t, err, "decode %s", file.Name())

			object, ok := obj.(client.Object)
			require.True(t, ok, "decode %s: expected Kubernetes object, got %T", file.Name(), obj)
			objects = append(objects, object)
		}

		require.NoError(t, f.Close())
	}
	return objects
}
