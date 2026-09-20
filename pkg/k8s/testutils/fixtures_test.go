// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestReadObjectsDir(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a-objects.yaml"), []byte(`
apiVersion: v1
kind: Service
metadata:
  name: first
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: second
`), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b-object.yaml"), []byte(`
apiVersion: v1
kind: Service
metadata:
  name: third
`), 0644))

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	objects := ReadObjectsDir(t, dir, scheme)
	require.Len(t, objects, 3)
	require.Equal(t, "first", objects[0].GetName())
	require.Equal(t, "second", objects[1].GetName())
	require.Equal(t, "third", objects[2].GetName())
}
