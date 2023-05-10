// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package bpf

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/spanstat"
)

// createMap wraps a call to ebpf.NewMapWithOptions while measuring syscall duration.
func createMap(spec *ebpf.MapSpec, opts *ebpf.MapOptions) (*ebpf.Map, error) {
	if opts == nil {
		opts = &ebpf.MapOptions{}
	}

	var duration *spanstat.SpanStat
	if option.Config.MetricsConfig.BPFSyscallDurationEnabled {
		duration = spanstat.Start()
	}

	m, err := ebpf.NewMapWithOptions(spec, *opts)

	if option.Config.MetricsConfig.BPFSyscallDurationEnabled {
		metrics.BPFSyscallDuration.WithLabelValues(metricOpCreate, metrics.Error2Outcome(err)).Observe(duration.End(err == nil).Total().Seconds())
	}

	return m, err
}

// This struct must be in sync with union bpf_attr's anonymous struct used by
// BPF_MAP_*_ELEM commands
type bpfAttrMapOpElem struct {
	mapFd uint32
	pad0  [4]byte
	key   uint64
	value uint64 // union: value or next_key
	flags uint64
}

// UpdateElementFromPointers updates the map in fd with the given value in the given key.
func UpdateElementFromPointers(fd int, mapName string, structPtr unsafe.Pointer, sizeOfStruct uintptr) error {
	var duration *spanstat.SpanStat
	if option.Config.MetricsConfig.BPFSyscallDurationEnabled {
		duration = spanstat.Start()
	}
	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_UPDATE_ELEM,
		uintptr(structPtr),
		sizeOfStruct,
	)
	runtime.KeepAlive(structPtr)
	if option.Config.MetricsConfig.BPFSyscallDurationEnabled {
		metrics.BPFSyscallDuration.WithLabelValues(metricOpUpdate, metrics.Errno2Outcome(err)).Observe(duration.End(err == 0).Total().Seconds())
	}

	if ret != 0 || err != 0 {
		switch err {
		case unix.E2BIG:
			return fmt.Errorf("Unable to update element for %s map with file descriptor %d: the map is full, please consider resizing it. %w", mapName, fd, err)
		case unix.EEXIST:
			return fmt.Errorf("Unable to update element for %s map with file descriptor %d: specified key already exists. %w", mapName, fd, err)
		case unix.ENOENT:
			return fmt.Errorf("Unable to update element for %s map with file descriptor %d: key does not exist. %w", mapName, fd, err)
		default:
			return fmt.Errorf("Unable to update element for %s map with file descriptor %d: %w", mapName, fd, err)
		}
	}

	return nil
}

// UpdateElement updates the map in fd with the given value in the given key.
// The flags can have the following values:
// bpf.BPF_ANY to create new element or update existing;
// bpf.BPF_NOEXIST to create new element if it didn't exist;
// bpf.BPF_EXIST to update existing element.
// Deprecated, use UpdateElementFromPointers
func UpdateElement(fd int, mapName string, key, value unsafe.Pointer, flags uint64) error {
	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(key)),
		value: uint64(uintptr(value)),
		flags: uint64(flags),
	}

	ret := UpdateElementFromPointers(fd, mapName, unsafe.Pointer(&uba), unsafe.Sizeof(uba))
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	return ret
}

func objCheck(fd int, path string, mapType MapType, keySize, valueSize, maxEntries, flags uint32) bool {
	info, err := GetMapInfo(os.Getpid(), fd)
	if err != nil {
		return false
	}

	scopedLog := log.WithField(logfields.Path, path)
	mismatch := false

	if info.MapType != mapType {
		scopedLog.WithFields(logrus.Fields{
			"old": info.MapType,
			"new": mapType,
		}).Warning("Map type mismatch for BPF map")
		mismatch = true
	}

	if info.KeySize != keySize {
		scopedLog.WithFields(logrus.Fields{
			"old": info.KeySize,
			"new": keySize,
		}).Warning("Key-size mismatch for BPF map")
		mismatch = true
	}

	if info.ValueSize != valueSize {
		scopedLog.WithFields(logrus.Fields{
			"old": info.ValueSize,
			"new": valueSize,
		}).Warning("Value-size mismatch for BPF map")
		mismatch = true
	}

	if info.MaxEntries != maxEntries {
		scopedLog.WithFields(logrus.Fields{
			"old": info.MaxEntries,
			"new": maxEntries,
		}).Warning("Max entries mismatch for BPF map")
		mismatch = true
	}
	if info.Flags != flags {
		scopedLog.WithFields(logrus.Fields{
			"old": info.Flags,
			"new": flags,
		}).Warning("Flags mismatch for BPF map")
		mismatch = true
	}

	if mismatch {
		if info.MapType == MapTypeProgArray {
			return false
		}

		scopedLog.Warning("Removing map to allow for property upgrade (expect map data loss)")

		// Kernel still holds map reference count via attached prog.
		// Only exception is prog array, but that is already resolved
		// differently.
		os.Remove(path)
		return true
	}

	return false
}

// OpenOrCreateMap attempts to load the pinned map at "pinDir/<spec.Name>" if
// the spec is marked as Pinned. Any parent directories of pinDir are
// automatically created. Any pinned maps incompatible with the given spec are
// removed and recreated.
//
// If spec.Pinned is 0, a new Map is always created.
func OpenOrCreateMap(spec *ebpf.MapSpec, pinDir string) (*ebpf.Map, error) {
	var opts ebpf.MapOptions
	if spec.Pinning != 0 {
		if pinDir == "" {
			return nil, errors.New("cannot pin map to empty pinDir")
		}
		if spec.Name == "" {
			return nil, errors.New("cannot load unnamed map from pin")
		}

		if err := os.MkdirAll(pinDir, 0755); err != nil {
			return nil, fmt.Errorf("creating map base pinning directory: %w", err)
		}

		opts.PinPath = pinDir
	}

	m, err := createMap(spec, &opts)
	if errors.Is(err, ebpf.ErrMapIncompatible) {
		// Found incompatible map. Open the pin again to find out why.
		m, err := ebpf.LoadPinnedMap(path.Join(pinDir, spec.Name), nil)
		if err != nil {
			return nil, fmt.Errorf("open pin of incompatible map: %w", err)
		}
		defer m.Close()

		log.WithField(logfields.Path, path.Join(pinDir, spec.Name)).
			WithFields(logrus.Fields{
				"old": fmt.Sprintf("Type:%s KeySize:%d ValueSize:%d MaxEntries:%d Flags:%d",
					m.Type(), m.KeySize(), m.ValueSize(), m.MaxEntries(), m.Flags()),
				"new": fmt.Sprintf("Type:%s KeySize:%d ValueSize:%d MaxEntries:%d Flags:%d",
					spec.Type, spec.KeySize, spec.ValueSize, spec.MaxEntries, spec.Flags),
			}).Info("Unpinning map with incompatible properties")

		// Existing map incompatible with spec. Unpin so it can be recreated.
		if err := m.Unpin(); err != nil {
			return nil, err
		}

		return createMap(spec, &opts)
	}

	return m, err
}

// GetMtime returns monotonic time that can be used to compare
// values with ktime_get_ns() BPF helper, e.g. needed to check
// the timeout in sec for BPF entries. We return the raw nsec,
// although that is not quite usable for comparison. Go has
// runtime.nanotime() but doesn't expose it as API.
func GetMtime() (uint64, error) {
	var ts unix.Timespec

	err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	if err != nil {
		return 0, fmt.Errorf("Unable get time: %s", err)
	}

	return uint64(unix.TimespecToNsec(ts)), nil
}

const (
	TimerInfoFilepath = "/proc/timer_list"
)

// GetJtime returns a close-enough approximation of kernel jiffies
// that can be used to compare against jiffies BPF helper. We parse
// it from /proc/timer_list. GetJtime() should be invoked only at
// mid-low frequencies.
func GetJtime() (uint64, error) {
	jiffies := uint64(0)
	scaler := uint64(8)
	timers, err := os.Open(TimerInfoFilepath)
	if err != nil {
		return 0, err
	}
	defer timers.Close()
	scanner := bufio.NewScanner(timers)
	for scanner.Scan() {
		tmp := uint64(0)
		n, _ := fmt.Sscanf(scanner.Text(), "jiffies: %d\n", &tmp)
		if n == 1 {
			jiffies = tmp
			break
		}
	}
	return jiffies >> scaler, scanner.Err()
}

type bpfAttrProg struct {
	ProgType    uint32
	InsnCnt     uint32
	Insns       uintptr
	License     uintptr
	LogLevel    uint32
	LogSize     uint32
	LogBuf      uintptr
	KernVersion uint32
	Flags       uint32
	Name        [16]byte
	Ifindex     uint32
	AttachType  uint32
}

type bpfAttachProg struct {
	TargetFd    uint32
	AttachFd    uint32
	AttachType  uint32
	AttachFlags uint32
}

// TestDummyProg loads a minimal BPF program into the kernel and probes
// whether it succeeds in doing so. This can be used to bail out early
// in the daemon when a given type is not supported.
func TestDummyProg(progType ProgType, attachType uint32) error {
	insns := []byte{
		// R0 = 1; EXIT
		0xb7, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	license := []byte{'A', 'S', 'L', '2', '\x00'}
	bpfAttr := bpfAttrProg{
		ProgType:   uint32(progType),
		AttachType: uint32(attachType),
		InsnCnt:    uint32(len(insns) / 8),
		Insns:      uintptr(unsafe.Pointer(&insns[0])),
		License:    uintptr(unsafe.Pointer(&license[0])),
	}

	fd, _, errno := unix.Syscall(unix.SYS_BPF, BPF_PROG_LOAD,
		uintptr(unsafe.Pointer(&bpfAttr)),
		unsafe.Sizeof(bpfAttr))

	if errno == 0 {
		defer unix.Close(int(fd))
		bpfAttr := bpfAttachProg{
			TargetFd:   uint32(os.Stdin.Fd()),
			AttachFd:   uint32(fd),
			AttachType: attachType,
		}
		// We also need to go and probe the kernel whether we can actually
		// attach something to make sure CONFIG_CGROUP_BPF is compiled in.
		// The behavior is that when compiled in, we'll get a EBADF via
		// cgroup_bpf_prog_attach() -> cgroup_get_from_fd(), otherwise when
		// compiled out, we'll get EINVAL.
		ret, _, errno := unix.Syscall(unix.SYS_BPF, BPF_PROG_ATTACH,
			uintptr(unsafe.Pointer(&bpfAttr)),
			unsafe.Sizeof(bpfAttr))
		if int(ret) < 0 && errno != unix.EBADF {
			return errno
		}
		return nil
	}

	runtime.KeepAlive(&insns)
	runtime.KeepAlive(&license)
	runtime.KeepAlive(&bpfAttr)

	return errno
}
