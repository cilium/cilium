// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probes

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestHaveAttachType(t *testing.T) {
	testutils.PrivilegedTest(t)

	testCases := []struct {
		pt      ebpf.ProgramType
		at      ebpf.AttachType
		version string
	}{
		// Table based on probes executed by the agent on startup.
		{ebpf.CGroupSockAddr, ebpf.AttachCGroupInet4Connect, "4.17"},
		{ebpf.CGroupSockAddr, ebpf.AttachCGroupInet6Connect, "4.17"},
		{ebpf.CGroupSockAddr, ebpf.AttachCGroupUDP4Recvmsg, "4.19.57"},
		{ebpf.CGroupSockAddr, ebpf.AttachCGroupUDP6Recvmsg, "4.19.57"},
		{ebpf.CGroupSockAddr, ebpf.AttachCgroupInet4GetPeername, "5.8"},
		{ebpf.CGroupSockAddr, ebpf.AttachCgroupInet6GetPeername, "5.8"},
	}
	for _, tt := range testCases {
		t.Run(fmt.Sprintf("%s_%s_%s", tt.version, tt.pt, tt.at), func(t *testing.T) {
			testutils.SkipOnOldKernel(t, tt.version, fmt.Sprintf("%s/%s", tt.pt, tt.at))

			if err := HaveAttachType(tt.pt, tt.at); err != nil {
				t.Fatalf("kernel doesn't support %s/%s: %s", tt.pt, tt.at, err)
			}
		})
	}
}

func TestHaveAttachTypeUnsupported(t *testing.T) {
	testutils.PrivilegedTest(t)

	if err := HaveAttachType(ebpf.CGroupSockAddr, ^ebpf.AttachType(0)); !errors.Is(err, ebpf.ErrNotSupported) {
		t.Fatal("unexpected successful probe for nonexistent attach type")
	}
}
