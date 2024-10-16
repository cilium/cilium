// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package cpumap

import (
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestCPUMap(t *testing.T) {
	testutils.PrivilegedTest(t)

	bpf.CheckOrMountFS("")
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Errorf("unable to remove memlock: %s", err.Error())
		t.Fail()
	}

	// Do we get an error if the config says its disabled?
	cpuMap := createCPUMap(
		hivetest.Lifecycle(t),
		Config{
			numCPUs: uint(runtime.NumCPU()),
			qsize:   1,
			enabled: false,
		},
		ebpf.PinNone,
	)

	if err := cpuMap.Populate(); err == nil {
		t.Error("expected error from cpuMap.Populate when enabled=flase")
		t.FailNow()
	}

	// Does the CPUMap return an error if the number of cpus on the system
	// doesn't match the number of entries in the map?
	cpuMap = createCPUMap(
		hivetest.Lifecycle(t),
		Config{
			numCPUs: 1,
			qsize:   1,
			enabled: true,
		},
		ebpf.PinNone,
	)
	cpuMap.cfg.numCPUs = 2

	if err := cpuMap.Populate(); err == nil {
		t.Error("expected error from cpuMap.Populate when cpu count mismatch")
		t.FailNow()
	}

	// Can the CPUMap call populate without an error when all conditions are
	// as expected?
	cpuMap = createCPUMap(
		hivetest.Lifecycle(t),
		Config{
			numCPUs: uint(runtime.NumCPU()),
			qsize:   1,
			enabled: true,
		},
		ebpf.PinNone,
	)

	if err := cpuMap.Populate(); err != nil {
		t.Error(err)
		t.FailNow()
	}
}
