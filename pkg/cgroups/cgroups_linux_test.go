// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cgroups

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/mountinfo"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestCgroup2RootFlags(t *testing.T) {
	for _, tc := range []struct {
		name  string
		infos []*mountinfo.MountInfo
		want  string
	}{
		{
			name: "root flags",
			infos: []*mountinfo.MountInfo{
				{FilesystemType: "tmpfs", SuperOptions: "rw,size=1024k"},
				{FilesystemType: "cgroup2", SuperOptions: "rw,nsdelegate,memory_recursiveprot"},
			},
			want: "nsdelegate,memory_recursiveprot",
		},
		{
			name:  "no root flags",
			infos: []*mountinfo.MountInfo{{FilesystemType: "cgroup2", SuperOptions: "rw"}},
			want:  "",
		},
		{
			name:  "no cgroup2 mount",
			infos: []*mountinfo.MountInfo{{FilesystemType: "cgroup", SuperOptions: "rw,memory"}},
			want:  "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, cgroup2RootFlags(tc.infos))
		})
	}
}

func TestPrivilegedMountCgroupKeepsRootFlags(t *testing.T) {
	testutils.PrivilegedTest(t)

	rootFlags := func() string {
		infos, err := mountinfo.GetMountInfo()
		require.NoError(t, err)
		return cgroup2RootFlags(infos)
	}
	before := rootFlags()
	if before == "" {
		t.Skip("no cgroup2 root flags are set on this host")
	}

	oldRoot := cgroupRoot
	t.Cleanup(func() { setCgroupRoot(oldRoot) })
	dir := t.TempDir()
	require.NoError(t, cgrpCheckOrMountLocation(dir))
	t.Cleanup(func() { unix.Unmount(dir, unix.MNT_DETACH) })

	require.Equal(t, before, rootFlags())
}
