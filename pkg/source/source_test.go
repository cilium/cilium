// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package source

import (
	"context"
	"log/slog"
	"testing"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
)

func TestAllowOverwrite(t *testing.T) {
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelError))
	h := hive.New(
		cell.Invoke(NewSources),
	)
	require.NoError(t, h.Start(log, context.TODO()))
	t.Cleanup(func() {
		h.Stop(log, context.TODO())
	})
	testAllowOverwrite(t)
}

func testAllowOverwrite(t *testing.T) {
	require.True(t, AllowOverwrite(Kubernetes, Kubernetes))
	require.True(t, AllowOverwrite(Kubernetes, CustomResource))
	require.True(t, AllowOverwrite(Kubernetes, KVStore))
	require.True(t, AllowOverwrite(Kubernetes, Local))
	require.True(t, AllowOverwrite(Kubernetes, KubeAPIServer))
	require.False(t, AllowOverwrite(Kubernetes, ClusterMesh))
	require.False(t, AllowOverwrite(Kubernetes, Directory))
	require.False(t, AllowOverwrite(Kubernetes, LocalAPI))
	require.False(t, AllowOverwrite(Kubernetes, Generated))
	require.False(t, AllowOverwrite(Kubernetes, Restored))
	require.False(t, AllowOverwrite(Kubernetes, Unspec))

	require.True(t, AllowOverwrite(CustomResource, CustomResource))
	require.True(t, AllowOverwrite(CustomResource, KVStore))
	require.True(t, AllowOverwrite(CustomResource, Local))
	require.True(t, AllowOverwrite(CustomResource, KubeAPIServer))
	require.False(t, AllowOverwrite(CustomResource, ClusterMesh))
	require.False(t, AllowOverwrite(CustomResource, Directory))
	require.False(t, AllowOverwrite(CustomResource, LocalAPI))
	require.False(t, AllowOverwrite(CustomResource, Kubernetes))
	require.False(t, AllowOverwrite(CustomResource, Generated))
	require.False(t, AllowOverwrite(CustomResource, Restored))
	require.False(t, AllowOverwrite(CustomResource, Unspec))

	require.False(t, AllowOverwrite(KVStore, Kubernetes))
	require.False(t, AllowOverwrite(KVStore, CustomResource))
	require.True(t, AllowOverwrite(KVStore, KVStore))
	require.True(t, AllowOverwrite(KVStore, Local))
	require.True(t, AllowOverwrite(KVStore, KubeAPIServer))
	require.False(t, AllowOverwrite(KVStore, ClusterMesh))
	require.False(t, AllowOverwrite(KVStore, Directory))
	require.False(t, AllowOverwrite(KVStore, LocalAPI))
	require.False(t, AllowOverwrite(KVStore, Generated))
	require.False(t, AllowOverwrite(KVStore, Restored))
	require.False(t, AllowOverwrite(KVStore, Unspec))

	require.False(t, AllowOverwrite(Local, Kubernetes))
	require.False(t, AllowOverwrite(Local, CustomResource))
	require.False(t, AllowOverwrite(Local, KVStore))
	require.False(t, AllowOverwrite(Local, Generated))
	require.True(t, AllowOverwrite(Local, Local))
	require.True(t, AllowOverwrite(Local, KubeAPIServer))
	require.False(t, AllowOverwrite(Local, ClusterMesh))
	require.False(t, AllowOverwrite(Local, Directory))
	require.False(t, AllowOverwrite(Local, LocalAPI))
	require.False(t, AllowOverwrite(Local, Restored))
	require.False(t, AllowOverwrite(Local, Unspec))

	require.False(t, AllowOverwrite(KubeAPIServer, Kubernetes))
	require.False(t, AllowOverwrite(KubeAPIServer, CustomResource))
	require.False(t, AllowOverwrite(KubeAPIServer, KVStore))
	require.False(t, AllowOverwrite(KubeAPIServer, Generated))
	require.False(t, AllowOverwrite(KubeAPIServer, Local))
	require.True(t, AllowOverwrite(KubeAPIServer, KubeAPIServer))
	require.False(t, AllowOverwrite(KubeAPIServer, ClusterMesh))
	require.False(t, AllowOverwrite(KubeAPIServer, Directory))
	require.False(t, AllowOverwrite(KubeAPIServer, LocalAPI))
	require.False(t, AllowOverwrite(KubeAPIServer, Restored))
	require.False(t, AllowOverwrite(KubeAPIServer, Unspec))

	require.True(t, AllowOverwrite(LocalAPI, Kubernetes))
	require.True(t, AllowOverwrite(LocalAPI, CustomResource))
	require.True(t, AllowOverwrite(LocalAPI, KVStore))
	require.True(t, AllowOverwrite(LocalAPI, Local))
	require.True(t, AllowOverwrite(LocalAPI, KubeAPIServer))
	require.True(t, AllowOverwrite(LocalAPI, ClusterMesh))
	require.True(t, AllowOverwrite(LocalAPI, Directory))
	require.True(t, AllowOverwrite(LocalAPI, LocalAPI))
	require.False(t, AllowOverwrite(LocalAPI, Generated))
	require.False(t, AllowOverwrite(LocalAPI, Restored))
	require.False(t, AllowOverwrite(LocalAPI, Unspec))

	require.True(t, AllowOverwrite(Generated, Kubernetes))
	require.True(t, AllowOverwrite(Generated, CustomResource))
	require.True(t, AllowOverwrite(Generated, KVStore))
	require.True(t, AllowOverwrite(Generated, Local))
	require.True(t, AllowOverwrite(Generated, KubeAPIServer))
	require.True(t, AllowOverwrite(Generated, ClusterMesh))
	require.True(t, AllowOverwrite(Generated, Directory))
	require.True(t, AllowOverwrite(Generated, LocalAPI))
	require.True(t, AllowOverwrite(Generated, Generated))
	require.False(t, AllowOverwrite(Generated, Restored))
	require.False(t, AllowOverwrite(Generated, Unspec))

	require.True(t, AllowOverwrite(Restored, Kubernetes))
	require.True(t, AllowOverwrite(Restored, CustomResource))
	require.True(t, AllowOverwrite(Restored, KVStore))
	require.True(t, AllowOverwrite(Restored, Local))
	require.True(t, AllowOverwrite(Restored, KubeAPIServer))
	require.True(t, AllowOverwrite(Restored, ClusterMesh))
	require.True(t, AllowOverwrite(Restored, Directory))
	require.True(t, AllowOverwrite(Restored, LocalAPI))
	require.True(t, AllowOverwrite(Restored, Generated))
	require.True(t, AllowOverwrite(Restored, Restored))
	require.False(t, AllowOverwrite(Restored, Unspec))

	require.True(t, AllowOverwrite(Directory, Kubernetes))
	require.True(t, AllowOverwrite(Directory, CustomResource))
	require.True(t, AllowOverwrite(Directory, KVStore))
	require.True(t, AllowOverwrite(Directory, Local))
	require.True(t, AllowOverwrite(Directory, KubeAPIServer))
	require.True(t, AllowOverwrite(Directory, ClusterMesh))
	require.True(t, AllowOverwrite(Directory, Directory))
	require.False(t, AllowOverwrite(Directory, LocalAPI))
	require.False(t, AllowOverwrite(Directory, Generated))
	require.False(t, AllowOverwrite(Directory, Restored))
	require.False(t, AllowOverwrite(Directory, Unspec))

	require.True(t, AllowOverwrite(Unspec, Kubernetes))
	require.True(t, AllowOverwrite(Unspec, CustomResource))
	require.True(t, AllowOverwrite(Unspec, KVStore))
	require.True(t, AllowOverwrite(Unspec, Local))
	require.True(t, AllowOverwrite(Unspec, KubeAPIServer))
	require.True(t, AllowOverwrite(Unspec, ClusterMesh))
	require.True(t, AllowOverwrite(Unspec, Directory))
	require.True(t, AllowOverwrite(Unspec, LocalAPI))
	require.True(t, AllowOverwrite(Unspec, Generated))
	require.True(t, AllowOverwrite(Unspec, Restored))
	require.True(t, AllowOverwrite(Unspec, Unspec))

	require.True(t, AllowOverwrite(ClusterMesh, Kubernetes))
	require.True(t, AllowOverwrite(ClusterMesh, CustomResource))
	require.True(t, AllowOverwrite(ClusterMesh, KVStore))
	require.True(t, AllowOverwrite(ClusterMesh, Local))
	require.True(t, AllowOverwrite(ClusterMesh, KubeAPIServer))
	require.True(t, AllowOverwrite(ClusterMesh, ClusterMesh))
	require.False(t, AllowOverwrite(ClusterMesh, Directory))
	require.False(t, AllowOverwrite(ClusterMesh, LocalAPI))
	require.False(t, AllowOverwrite(ClusterMesh, Generated))
	require.False(t, AllowOverwrite(ClusterMesh, Restored))
	require.False(t, AllowOverwrite(ClusterMesh, Unspec))
}
