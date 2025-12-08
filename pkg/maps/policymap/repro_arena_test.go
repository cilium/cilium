package policymap

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func TestArenaMapVerification(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	// 1. Create Arena Map
	spec := &ebpf.MapSpec{
		Name:       "test_arena_map",
		Type:       ebpf.MapType(33), // BPF_MAP_TYPE_ARENA
		KeySize:    0,
		ValueSize:  0,
		MaxEntries: 10,      // Small size
		Flags:      1 << 10, // BPF_F_MMAPABLE
	}

	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Skipf("Skipping test, Arena map creation failed (kernel might not support it): %v", err)
	}
	defer m.Close()

	// 2. Mmap the map
	t.Log("Mmapping the map...")
	pageSize := unix.Getpagesize()
	b, err := unix.Mmap(m.FD(), 0, pageSize*10, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatalf("Mmap failed: %v", err)
	}
	t.Log("Mmap succeeded")

	// 3. Unmap
	t.Log("Unmapping the map...")
	unix.Munmap(b)
}
