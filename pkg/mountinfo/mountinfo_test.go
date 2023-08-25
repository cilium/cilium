// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package mountinfo

import (
	"bytes"
	"testing"

	. "github.com/cilium/checkmate"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/checker"
)

const (
	mountInfoContent = `21 68 0:20 / /sys rw,nosuid,nodev,noexec,relatime shared:2 - sysfs sysfs rw
22 68 0:4 / /proc rw,nosuid,nodev,noexec,relatime shared:23 - proc proc rw
23 68 0:6 / /dev rw,nosuid shared:19 - devtmpfs devtmpfs rw,size=8023924k,nr_inodes=2005981,mode=755
24 21 0:7 / /sys/kernel/security rw,nosuid,nodev,noexec,relatime shared:3 - securityfs securityfs rw
25 23 0:21 / /dev/shm rw,nosuid,nodev shared:20 - tmpfs tmpfs rw
26 23 0:22 / /dev/pts rw,nosuid,noexec,relatime shared:21 - devpts devpts rw,gid=5,mode=620,ptmxmode=000
27 68 0:23 / /run rw,nosuid,nodev shared:22 - tmpfs tmpfs rw,mode=755
28 21 0:24 / /sys/fs/cgroup ro,nosuid,nodev,noexec shared:4 - tmpfs tmpfs ro,mode=755
29 28 0:25 / /sys/fs/cgroup/unified rw,nosuid,nodev,noexec,relatime shared:5 - cgroup2 cgroup rw,nsdelegate
30 28 0:26 / /sys/fs/cgroup/systemd rw,nosuid,nodev,noexec,relatime shared:6 - cgroup cgroup rw,xattr,name=systemd
31 21 0:27 / /sys/fs/pstore rw,nosuid,nodev,noexec,relatime shared:18 - pstore pstore rw
32 28 0:28 / /sys/fs/cgroup/blkio rw,nosuid,nodev,noexec,relatime shared:7 - cgroup cgroup rw,blkio
33 28 0:29 / /sys/fs/cgroup/pids rw,nosuid,nodev,noexec,relatime shared:8 - cgroup cgroup rw,pids
34 28 0:30 / /sys/fs/cgroup/net_cls,net_prio rw,nosuid,nodev,noexec,relatime shared:9 - cgroup cgroup rw,net_cls,net_prio
35 28 0:31 / /sys/fs/cgroup/freezer rw,nosuid,nodev,noexec,relatime shared:10 - cgroup cgroup rw,freezer
36 28 0:32 / /sys/fs/cgroup/rdma rw,nosuid,nodev,noexec,relatime shared:11 - cgroup cgroup rw,rdma
37 28 0:33 / /sys/fs/cgroup/cpu,cpuacct rw,nosuid,nodev,noexec,relatime shared:12 - cgroup cgroup rw,cpu,cpuacct
38 28 0:34 / /sys/fs/cgroup/cpuset rw,nosuid,nodev,noexec,relatime shared:13 - cgroup cgroup rw,cpuset
39 28 0:35 / /sys/fs/cgroup/hugetlb rw,nosuid,nodev,noexec,relatime shared:14 - cgroup cgroup rw,hugetlb
40 28 0:36 / /sys/fs/cgroup/devices rw,nosuid,nodev,noexec,relatime shared:15 - cgroup cgroup rw,devices
41 28 0:37 / /sys/fs/cgroup/perf_event rw,nosuid,nodev,noexec,relatime shared:16 - cgroup cgroup rw,perf_event
42 28 0:38 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:17 - cgroup cgroup rw,memory
68 0 254:1 / / rw,relatime shared:1 - xfs /dev/mapper/system-root rw,attr2,inode64,noquota
43 22 0:41 / /proc/sys/fs/binfmt_misc rw,relatime shared:24 - autofs systemd-1 rw,fd=35,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=16155
44 23 0:42 / /dev/hugepages rw,relatime shared:25 - hugetlbfs hugetlbfs rw,pagesize=2M
45 23 0:19 / /dev/mqueue rw,relatime shared:26 - mqueue mqueue rw
46 21 0:8 / /sys/kernel/debug rw,relatime shared:27 - debugfs debugfs rw
78 68 8:1 / /boot rw,relatime shared:28 - ext4 /dev/sda1 rw,stripe=4
80 68 254:3 / /home rw,relatime shared:29 - xfs /dev/mapper/system-home rw,attr2,inode64,noquota
382 27 0:47 / /run/user/463 rw,nosuid,nodev,relatime shared:294 - tmpfs tmpfs rw,size=1606744k,mode=700,uid=463,gid=463
472 27 0:48 / /run/user/1000 rw,nosuid,nodev,relatime shared:380 - tmpfs tmpfs rw,size=1606744k,mode=700,uid=1000,gid=100
485 21 0:49 / /sys/fs/fuse/connections rw,relatime shared:391 - fusectl fusectl rw
497 472 0:50 / /run/user/1000/gvfs rw,nosuid,nodev,relatime shared:401 - fuse.gvfsd-fuse gvfsd-fuse rw,user_id=1000,group_id=100
510 46 0:11 / /sys/kernel/debug/tracing rw,relatime shared:412 - tracefs tracefs rw
225 472 0:45 / /run/user/1000/doc rw,nosuid,nodev,relatime shared:141 - fuse /dev/fuse rw,user_id=1000,group_id=100
655 68 0:100 / /var/lib/docker/overlay2/209d7aafdafc7ebde84cb9f993c1e34cf0376f4f15dae4ddd2dd260b8d987d4d/merged rw,relatime shared:150 - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/MX2FFSUOIXOBNUCHC33QEQNNX2:/var/lib/docker/overlay2/l/Q3SPWQ6QMC22TK7SPQOLSVHLUQ:/var/lib/docker/overlay2/l/SPVXNCJEV3EQJGMHEOQGTLNDRT:/var/lib/docker/overlay2/l/EFMD4SE3UNOSVMNMD7EOGIIL5I:/var/lib/docker/overlay2/l/SFK3LVVM7XUXJWRS6I75TSS2DI:/var/lib/docker/overlay2/l/GL3CZA4OB3YI7A6JKWOLVNESSL:/var/lib/docker/overlay2/l/L6OAE4YY2C6BKHH55W42V7T6Y7,upperdir=/var/lib/docker/overlay2/209d7aafdafc7ebde84cb9f993c1e34cf0376f4f15dae4ddd2dd260b8d987d4d/diff,workdir=/var/lib/docker/overlay2/209d7aafdafc7ebde84cb9f993c1e34cf0376f4f15dae4ddd2dd260b8d987d4d/work
810 68 0:107 / /var/lib/docker/containers/178dc073e1eb58e137d562d28928a187bdc05905ff889b7658dd7a9b3488e494/mounts/shm rw,nosuid,nodev,noexec,relatime shared:159 - tmpfs shm rw,size=65536k
1017 27 0:3 net:[4026532775] /run/docker/netns/85c40bc29e30 rw shared:168 - nsfs nsfs rw
969 68 0:117 / /var/lib/docker/overlay2/e35eafd51f5f1e5a1f055de47bfccae6bb47c57317628507bb00b0981d33d717/merged rw,relatime shared:177 - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/SRXSWY4NGUH5ZX5EHGZ3R72ZZZ:/var/lib/docker/overlay2/l/4MKSUFUR2WVKNR47LRVGQUHDIX:/var/lib/docker/overlay2/l/CGHCSEQRDDOB7LDRMW6DNKGYKF:/var/lib/docker/overlay2/l/KXCYX6NI6XSXSW3R6YRYOJIXJY:/var/lib/docker/overlay2/l/5SWRNPTBRYPDDHKFPKXBQJ3AGN:/var/lib/docker/overlay2/l/L6OAE4YY2C6BKHH55W42V7T6Y7,upperdir=/var/lib/docker/overlay2/e35eafd51f5f1e5a1f055de47bfccae6bb47c57317628507bb00b0981d33d717/diff,workdir=/var/lib/docker/overlay2/e35eafd51f5f1e5a1f055de47bfccae6bb47c57317628507bb00b0981d33d717/work
990 68 0:118 / /var/lib/docker/containers/eb56406256443e41d885581f36a790155bfa7eab49753a3cbeef6c12226fb7eb/mounts/shm rw,nosuid,nodev,noexec,relatime shared:249 - tmpfs shm rw,size=65536k
1110 27 0:3 net:[4026532846] /run/docker/netns/35b7f0885825 rw shared:258 - nsfs nsfs rw
657 21 0:98 / /sys/fs/bpf rw,relatime shared:267 - bpf bpffs rw`
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type MountInfoTestSuite struct{}

var _ = Suite(&MountInfoTestSuite{})

func (s *MountInfoTestSuite) TestParseMountInfoFile(c *C) {
	expectedLength := 42
	expectedMountInfos := []*MountInfo{
		{
			MountID:        21,
			ParentID:       68,
			StDev:          "0:20",
			Root:           "/",
			MountPoint:     "/sys",
			MountOptions:   "rw,nosuid,nodev,noexec,relatime",
			OptionalFields: []string{"shared:2"},
			FilesystemType: "sysfs",
			MountSource:    "sysfs",
			SuperOptions:   "rw",
		},
		{
			MountID:        22,
			ParentID:       68,
			StDev:          "0:4",
			Root:           "/",
			MountPoint:     "/proc",
			MountOptions:   "rw,nosuid,nodev,noexec,relatime",
			OptionalFields: []string{"shared:23"},
			FilesystemType: "proc",
			MountSource:    "proc",
			SuperOptions:   "rw",
		},
		{
			MountID:        23,
			ParentID:       68,
			StDev:          "0:6",
			Root:           "/",
			MountPoint:     "/dev",
			MountOptions:   "rw,nosuid",
			OptionalFields: []string{"shared:19"},
			FilesystemType: "devtmpfs",
			MountSource:    "devtmpfs",
			SuperOptions:   "rw,size=8023924k,nr_inodes=2005981,mode=755",
		},
		{
			MountID:        24,
			ParentID:       21,
			StDev:          "0:7",
			Root:           "/",
			MountPoint:     "/sys/kernel/security",
			MountOptions:   "rw,nosuid,nodev,noexec,relatime",
			OptionalFields: []string{"shared:3"},
			FilesystemType: "securityfs",
			MountSource:    "securityfs",
			SuperOptions:   "rw",
		},
		{
			MountID:        25,
			ParentID:       23,
			StDev:          "0:21",
			Root:           "/",
			MountPoint:     "/dev/shm",
			MountOptions:   "rw,nosuid,nodev",
			OptionalFields: []string{"shared:20"},
			FilesystemType: "tmpfs",
			MountSource:    "tmpfs",
			SuperOptions:   "rw",
		},
		{
			MountID:        26,
			ParentID:       23,
			StDev:          "0:22",
			Root:           "/",
			MountPoint:     "/dev/pts",
			MountOptions:   "rw,nosuid,noexec,relatime",
			OptionalFields: []string{"shared:21"},
			FilesystemType: "devpts",
			MountSource:    "devpts",
			SuperOptions:   "rw,gid=5,mode=620,ptmxmode=000",
		},
		{
			MountID:        27,
			ParentID:       68,
			StDev:          "0:23",
			Root:           "/",
			MountPoint:     "/run",
			MountOptions:   "rw,nosuid,nodev",
			OptionalFields: []string{"shared:22"},
			FilesystemType: "tmpfs",
			MountSource:    "tmpfs",
			SuperOptions:   "rw,mode=755",
		},
		{
			MountID:        28,
			ParentID:       21,
			StDev:          "0:24",
			Root:           "/",
			MountPoint:     "/sys/fs/cgroup",
			MountOptions:   "ro,nosuid,nodev,noexec",
			OptionalFields: []string{"shared:4"},
			FilesystemType: "tmpfs",
			MountSource:    "tmpfs",
			SuperOptions:   "ro,mode=755",
		},
		{
			MountID:        29,
			ParentID:       28,
			StDev:          "0:25",
			Root:           "/",
			MountPoint:     "/sys/fs/cgroup/unified",
			MountOptions:   "rw,nosuid,nodev,noexec,relatime",
			OptionalFields: []string{"shared:5"},
			FilesystemType: "cgroup2",
			MountSource:    "cgroup",
			SuperOptions:   "rw,nsdelegate",
		},
		{
			MountID:        30,
			ParentID:       28,
			StDev:          "0:26",
			Root:           "/",
			MountPoint:     "/sys/fs/cgroup/systemd",
			MountOptions:   "rw,nosuid,nodev,noexec,relatime",
			OptionalFields: []string{"shared:6"},
			FilesystemType: "cgroup",
			MountSource:    "cgroup",
			SuperOptions:   "rw,xattr,name=systemd",
		},
		{
			MountID:        31,
			ParentID:       21,
			StDev:          "0:27",
			Root:           "/",
			MountPoint:     "/sys/fs/pstore",
			MountOptions:   "rw,nosuid,nodev,noexec,relatime",
			OptionalFields: []string{"shared:18"},
			FilesystemType: "pstore",
			MountSource:    "pstore",
			SuperOptions:   "rw",
		},
		{
			MountID:        32,
			ParentID:       28,
			StDev:          "0:28",
			Root:           "/",
			MountPoint:     "/sys/fs/cgroup/blkio",
			MountOptions:   "rw,nosuid,nodev,noexec,relatime",
			OptionalFields: []string{"shared:7"},
			FilesystemType: "cgroup",
			MountSource:    "cgroup",
			SuperOptions:   "rw,blkio",
		},
		{
			MountID:        33,
			ParentID:       28,
			StDev:          "0:29",
			Root:           "/",
			MountPoint:     "/sys/fs/cgroup/pids",
			MountOptions:   "rw,nosuid,nodev,noexec,relatime",
			OptionalFields: []string{"shared:8"},
			FilesystemType: "cgroup",
			MountSource:    "cgroup",
			SuperOptions:   "rw,pids",
		},
		{
			MountID:        34,
			ParentID:       28,
			StDev:          "0:30",
			Root:           "/",
			MountPoint:     "/sys/fs/cgroup/net_cls,net_prio",
			MountOptions:   "rw,nosuid,nodev,noexec,relatime",
			OptionalFields: []string{"shared:9"},
			FilesystemType: "cgroup",
			MountSource:    "cgroup",
			SuperOptions:   "rw,net_cls,net_prio",
		},
		{
			MountID:        35,
			ParentID:       28,
			StDev:          "0:31",
			Root:           "/",
			MountPoint:     "/sys/fs/cgroup/freezer",
			MountOptions:   "rw,nosuid,nodev,noexec,relatime",
			OptionalFields: []string{"shared:10"},
			FilesystemType: "cgroup",
			MountSource:    "cgroup",
			SuperOptions:   "rw,freezer",
		},
		{
			MountID:        36,
			ParentID:       28,
			StDev:          "0:32",
			Root:           "/",
			MountPoint:     "/sys/fs/cgroup/rdma",
			MountOptions:   "rw,nosuid,nodev,noexec,relatime",
			OptionalFields: []string{"shared:11"},
			FilesystemType: "cgroup",
			MountSource:    "cgroup",
			SuperOptions:   "rw,rdma",
		},
		{
			MountID:        37,
			ParentID:       28,
			StDev:          "0:33",
			Root:           "/",
			MountPoint:     "/sys/fs/cgroup/cpu,cpuacct",
			MountOptions:   "rw,nosuid,nodev,noexec,relatime",
			OptionalFields: []string{"shared:12"},
			FilesystemType: "cgroup",
			MountSource:    "cgroup",
			SuperOptions:   "rw,cpu,cpuacct",
		},
		{
			MountID:        38,
			ParentID:       28,
			StDev:          "0:34",
			Root:           "/",
			MountPoint:     "/sys/fs/cgroup/cpuset",
			MountOptions:   "rw,nosuid,nodev,noexec,relatime",
			OptionalFields: []string{"shared:13"},
			FilesystemType: "cgroup",
			MountSource:    "cgroup",
			SuperOptions:   "rw,cpuset",
		},
		{
			MountID:        39,
			ParentID:       28,
			StDev:          "0:35",
			Root:           "/",
			MountPoint:     "/sys/fs/cgroup/hugetlb",
			MountOptions:   "rw,nosuid,nodev,noexec,relatime",
			OptionalFields: []string{"shared:14"},
			FilesystemType: "cgroup",
			MountSource:    "cgroup",
			SuperOptions:   "rw,hugetlb",
		},
		{
			MountID:        40,
			ParentID:       28,
			StDev:          "0:36",
			Root:           "/",
			MountPoint:     "/sys/fs/cgroup/devices",
			MountOptions:   "rw,nosuid,nodev,noexec,relatime",
			OptionalFields: []string{"shared:15"},
			FilesystemType: "cgroup",
			MountSource:    "cgroup",
			SuperOptions:   "rw,devices",
		},
		{
			MountID:        41,
			ParentID:       28,
			StDev:          "0:37",
			Root:           "/",
			MountPoint:     "/sys/fs/cgroup/perf_event",
			MountOptions:   "rw,nosuid,nodev,noexec,relatime",
			OptionalFields: []string{"shared:16"},
			FilesystemType: "cgroup",
			MountSource:    "cgroup",
			SuperOptions:   "rw,perf_event",
		},
		{
			MountID:        42,
			ParentID:       28,
			StDev:          "0:38",
			Root:           "/",
			MountPoint:     "/sys/fs/cgroup/memory",
			MountOptions:   "rw,nosuid,nodev,noexec,relatime",
			OptionalFields: []string{"shared:17"},
			FilesystemType: "cgroup",
			MountSource:    "cgroup",
			SuperOptions:   "rw,memory",
		},
		{
			MountID:        68,
			ParentID:       0,
			StDev:          "254:1",
			Root:           "/",
			MountPoint:     "/",
			MountOptions:   "rw,relatime",
			OptionalFields: []string{"shared:1"},
			FilesystemType: "xfs",
			MountSource:    "/dev/mapper/system-root",
			SuperOptions:   "rw,attr2,inode64,noquota",
		},
		{
			MountID:        43,
			ParentID:       22,
			StDev:          "0:41",
			Root:           "/",
			MountPoint:     "/proc/sys/fs/binfmt_misc",
			MountOptions:   "rw,relatime",
			OptionalFields: []string{"shared:24"},
			FilesystemType: "autofs",
			MountSource:    "systemd-1",
			SuperOptions:   "rw,fd=35,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=16155",
		},
		{
			MountID:        44,
			ParentID:       23,
			StDev:          "0:42",
			Root:           "/",
			MountPoint:     "/dev/hugepages",
			MountOptions:   "rw,relatime",
			OptionalFields: []string{"shared:25"},
			FilesystemType: "hugetlbfs",
			MountSource:    "hugetlbfs",
			SuperOptions:   "rw,pagesize=2M",
		},
		{
			MountID:        45,
			ParentID:       23,
			StDev:          "0:19",
			Root:           "/",
			MountPoint:     "/dev/mqueue",
			MountOptions:   "rw,relatime",
			OptionalFields: []string{"shared:26"},
			FilesystemType: "mqueue",
			MountSource:    "mqueue",
			SuperOptions:   "rw",
		},
		{
			MountID:        46,
			ParentID:       21,
			StDev:          "0:8",
			Root:           "/",
			MountPoint:     "/sys/kernel/debug",
			MountOptions:   "rw,relatime",
			OptionalFields: []string{"shared:27"},
			FilesystemType: "debugfs",
			MountSource:    "debugfs",
			SuperOptions:   "rw",
		},
		{
			MountID:        78,
			ParentID:       68,
			StDev:          "8:1",
			Root:           "/",
			MountPoint:     "/boot",
			MountOptions:   "rw,relatime",
			OptionalFields: []string{"shared:28"},
			FilesystemType: "ext4",
			MountSource:    "/dev/sda1",
			SuperOptions:   "rw,stripe=4",
		},
		{
			MountID:        80,
			ParentID:       68,
			StDev:          "254:3",
			Root:           "/",
			MountPoint:     "/home",
			MountOptions:   "rw,relatime",
			OptionalFields: []string{"shared:29"},
			FilesystemType: "xfs",
			MountSource:    "/dev/mapper/system-home",
			SuperOptions:   "rw,attr2,inode64,noquota",
		},
		{
			MountID:        382,
			ParentID:       27,
			StDev:          "0:47",
			Root:           "/",
			MountPoint:     "/run/user/463",
			MountOptions:   "rw,nosuid,nodev,relatime",
			OptionalFields: []string{"shared:294"},
			FilesystemType: "tmpfs",
			MountSource:    "tmpfs",
			SuperOptions:   "rw,size=1606744k,mode=700,uid=463,gid=463",
		},
		{
			MountID:        472,
			ParentID:       27,
			StDev:          "0:48",
			Root:           "/",
			MountPoint:     "/run/user/1000",
			MountOptions:   "rw,nosuid,nodev,relatime",
			OptionalFields: []string{"shared:380"},
			FilesystemType: "tmpfs",
			MountSource:    "tmpfs",
			SuperOptions:   "rw,size=1606744k,mode=700,uid=1000,gid=100",
		},
		{
			MountID:        485,
			ParentID:       21,
			StDev:          "0:49",
			Root:           "/",
			MountPoint:     "/sys/fs/fuse/connections",
			MountOptions:   "rw,relatime",
			OptionalFields: []string{"shared:391"},
			FilesystemType: "fusectl",
			MountSource:    "fusectl",
			SuperOptions:   "rw",
		},
		{
			MountID:        497,
			ParentID:       472,
			StDev:          "0:50",
			Root:           "/",
			MountPoint:     "/run/user/1000/gvfs",
			MountOptions:   "rw,nosuid,nodev,relatime",
			OptionalFields: []string{"shared:401"},
			FilesystemType: "fuse.gvfsd-fuse",
			MountSource:    "gvfsd-fuse",
			SuperOptions:   "rw,user_id=1000,group_id=100",
		},
		{
			MountID:        510,
			ParentID:       46,
			StDev:          "0:11",
			Root:           "/",
			MountPoint:     "/sys/kernel/debug/tracing",
			MountOptions:   "rw,relatime",
			OptionalFields: []string{"shared:412"},
			FilesystemType: "tracefs",
			MountSource:    "tracefs",
			SuperOptions:   "rw",
		},
		{
			MountID:        225,
			ParentID:       472,
			StDev:          "0:45",
			Root:           "/",
			MountPoint:     "/run/user/1000/doc",
			MountOptions:   "rw,nosuid,nodev,relatime",
			OptionalFields: []string{"shared:141"},
			FilesystemType: "fuse",
			MountSource:    "/dev/fuse",
			SuperOptions:   "rw,user_id=1000,group_id=100",
		},
		{
			MountID:        655,
			ParentID:       68,
			StDev:          "0:100",
			Root:           "/",
			MountPoint:     "/var/lib/docker/overlay2/209d7aafdafc7ebde84cb9f993c1e34cf0376f4f15dae4ddd2dd260b8d987d4d/merged",
			MountOptions:   "rw,relatime",
			OptionalFields: []string{"shared:150"},
			FilesystemType: "overlay",
			MountSource:    "overlay",
			SuperOptions:   "rw,lowerdir=/var/lib/docker/overlay2/l/MX2FFSUOIXOBNUCHC33QEQNNX2:/var/lib/docker/overlay2/l/Q3SPWQ6QMC22TK7SPQOLSVHLUQ:/var/lib/docker/overlay2/l/SPVXNCJEV3EQJGMHEOQGTLNDRT:/var/lib/docker/overlay2/l/EFMD4SE3UNOSVMNMD7EOGIIL5I:/var/lib/docker/overlay2/l/SFK3LVVM7XUXJWRS6I75TSS2DI:/var/lib/docker/overlay2/l/GL3CZA4OB3YI7A6JKWOLVNESSL:/var/lib/docker/overlay2/l/L6OAE4YY2C6BKHH55W42V7T6Y7,upperdir=/var/lib/docker/overlay2/209d7aafdafc7ebde84cb9f993c1e34cf0376f4f15dae4ddd2dd260b8d987d4d/diff,workdir=/var/lib/docker/overlay2/209d7aafdafc7ebde84cb9f993c1e34cf0376f4f15dae4ddd2dd260b8d987d4d/work",
		},
		{
			MountID:        810,
			ParentID:       68,
			StDev:          "0:107",
			Root:           "/",
			MountPoint:     "/var/lib/docker/containers/178dc073e1eb58e137d562d28928a187bdc05905ff889b7658dd7a9b3488e494/mounts/shm",
			MountOptions:   "rw,nosuid,nodev,noexec,relatime",
			OptionalFields: []string{"shared:159"},
			FilesystemType: "tmpfs",
			MountSource:    "shm",
			SuperOptions:   "rw,size=65536k",
		},
		{
			MountID:        1017,
			ParentID:       27,
			StDev:          "0:3",
			Root:           "net:[4026532775]",
			MountPoint:     "/run/docker/netns/85c40bc29e30",
			MountOptions:   "rw",
			OptionalFields: []string{"shared:168"},
			FilesystemType: "nsfs",
			MountSource:    "nsfs",
			SuperOptions:   "rw",
		},
		{
			MountID:        969,
			ParentID:       68,
			StDev:          "0:117",
			Root:           "/",
			MountPoint:     "/var/lib/docker/overlay2/e35eafd51f5f1e5a1f055de47bfccae6bb47c57317628507bb00b0981d33d717/merged",
			MountOptions:   "rw,relatime",
			OptionalFields: []string{"shared:177"},
			FilesystemType: "overlay",
			MountSource:    "overlay",
			SuperOptions:   "rw,lowerdir=/var/lib/docker/overlay2/l/SRXSWY4NGUH5ZX5EHGZ3R72ZZZ:/var/lib/docker/overlay2/l/4MKSUFUR2WVKNR47LRVGQUHDIX:/var/lib/docker/overlay2/l/CGHCSEQRDDOB7LDRMW6DNKGYKF:/var/lib/docker/overlay2/l/KXCYX6NI6XSXSW3R6YRYOJIXJY:/var/lib/docker/overlay2/l/5SWRNPTBRYPDDHKFPKXBQJ3AGN:/var/lib/docker/overlay2/l/L6OAE4YY2C6BKHH55W42V7T6Y7,upperdir=/var/lib/docker/overlay2/e35eafd51f5f1e5a1f055de47bfccae6bb47c57317628507bb00b0981d33d717/diff,workdir=/var/lib/docker/overlay2/e35eafd51f5f1e5a1f055de47bfccae6bb47c57317628507bb00b0981d33d717/work",
		},
		{
			MountID:        990,
			ParentID:       68,
			StDev:          "0:118",
			Root:           "/",
			MountPoint:     "/var/lib/docker/containers/eb56406256443e41d885581f36a790155bfa7eab49753a3cbeef6c12226fb7eb/mounts/shm",
			MountOptions:   "rw,nosuid,nodev,noexec,relatime",
			OptionalFields: []string{"shared:249"},
			FilesystemType: "tmpfs",
			MountSource:    "shm",
			SuperOptions:   "rw,size=65536k",
		},
		{
			MountID:        1110,
			ParentID:       27,
			StDev:          "0:3",
			Root:           "net:[4026532846]",
			MountPoint:     "/run/docker/netns/35b7f0885825",
			MountOptions:   "rw",
			OptionalFields: []string{"shared:258"},
			FilesystemType: "nsfs",
			MountSource:    "nsfs",
			SuperOptions:   "rw",
		},
		{
			MountID:        657,
			ParentID:       21,
			StDev:          "0:98",
			Root:           "/",
			MountPoint:     "/sys/fs/bpf",
			MountOptions:   "rw,relatime",
			OptionalFields: []string{"shared:267"},
			FilesystemType: "bpf",
			MountSource:    "bpffs",
			SuperOptions:   "rw",
		},
	}

	r := bytes.NewBuffer([]byte(mountInfoContent))
	mountInfos, err := parseMountInfoFile(r)
	c.Assert(err, IsNil)
	c.Assert(mountInfos, HasLen, expectedLength)
	c.Assert(mountInfos, checker.DeepEquals, expectedMountInfos)
}

func (s *MountInfoTestSuite) TestGetMountInfo(c *C) {
	_, err := GetMountInfo()
	c.Assert(err, IsNil)
}

// TestIsMountFS tests the public function IsMountFS. We cannot expect every
// system and machine to have any predictable mounts, but let's try a couple
// of very well known paths.
func (s *MountInfoTestSuite) TestIsMountFS(c *C) {
	mounted, matched, err := IsMountFS(unix.PROC_SUPER_MAGIC, "/proc")
	c.Assert(err, IsNil)
	c.Assert(mounted, Equals, true)
	c.Assert(matched, Equals, true)

	mounted, matched, err = IsMountFS(FilesystemTypeBPFFS, "/sys/fs/bpf")
	c.Assert(err, IsNil)
	// We can't expect /sys/fs/bpf is mounted, so only check fstype
	// if it is mounted. IOW, if /sys/fs/bpf is a mount point,
	// we expect it to be bpffs.
	if mounted {
		c.Assert(matched, Equals, true)
	}
}
