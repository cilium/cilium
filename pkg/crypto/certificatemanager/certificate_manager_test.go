// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package certificatemanager

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	k8sTestutils "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/policy/api"
)

func writeLocalSecret(t *testing.T, dir, value string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "value"), []byte(value), 0600))
}

func TestGetSecretString(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		secret    *api.Secret
		setup     func(t *testing.T, root string)
		wantValue string
		wantError bool
		wantErrIs error
	}{
		{
			name:      "valid local secret",
			namespace: "tenant",
			secret:    &api.Secret{Name: "test-secret"},
			setup: func(t *testing.T, root string) {
				writeLocalSecret(t, filepath.Join(root, "tenant", "test-secret"), "secret value")
			},
			wantValue: "secret value",
		},
		{
			name:      "name escapes certificates root",
			namespace: "tenant",
			secret:    &api.Secret{Name: "../../host-secret"},
			setup: func(t *testing.T, root string) {
				writeLocalSecret(t, filepath.Join(filepath.Dir(root), "host-secret"), "host secret")
			},
			wantErrIs: errInvalidSecretReference,
		},
		{
			name:      "namespace escapes certificates root",
			namespace: "tenant",
			secret:    &api.Secret{Namespace: "../host-secret", Name: "test-secret"},
			setup: func(t *testing.T, root string) {
				writeLocalSecret(t, filepath.Join(filepath.Dir(root), "host-secret", "test-secret"), "host secret")
			},
			wantErrIs: errInvalidSecretReference,
		},
		{
			name:      "symlink escapes certificates root",
			namespace: "tenant",
			secret:    &api.Secret{Name: "test-secret"},
			setup: func(t *testing.T, root string) {
				outside := filepath.Join(filepath.Dir(root), "outside")
				writeLocalSecret(t, outside, "host secret")
				require.NoError(t, os.MkdirAll(filepath.Join(root, "tenant"), 0755))
				require.NoError(t, os.Symlink(outside, filepath.Join(root, "tenant", "test-secret")))
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "certificates")
			require.NoError(t, os.MkdirAll(root, 0755))
			tt.setup(t, root)

			_, clientset := k8sTestutils.NewFakeClientset(hivetest.Logger(t))
			m := &manager{rootPath: root, k8sClient: clientset}
			value, err := m.GetSecretString(context.Background(), tt.secret, tt.namespace)

			if tt.wantErrIs != nil {
				require.ErrorIs(t, err, tt.wantErrIs)
			} else if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.wantValue, value)
		})
	}
}
