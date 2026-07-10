// Package platform includes runtime-specific code needed for the compiler or otherwise.
package platform

import (
	"runtime"

	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
)

// CompilerSupported includes constraints here and also the assembler.
func CompilerSupported() bool {
	return CompilerSupports(api.CoreFeaturesV2)
}

func CompilerSupports(features api.CoreFeatures) bool {
	if !compilerPlatformSupports(features) {
		return false
	}
	// Won't panic
	return executableMmapSupported()
}

func compilerPlatformSupports(features api.CoreFeatures) bool {
	switch runtime.GOOS {
	case "linux", "darwin", "freebsd", "netbsd", "windows":
		if runtime.GOARCH == "arm64" {
			if features.IsEnabled(experimental.CoreFeaturesThreads) {
				return CpuFeatures.Has(CpuFeatureArm64Atomic)
			}
			return true
		}
		fallthrough
	case "dragonfly", "solaris", "illumos":
		return runtime.GOARCH == "amd64" && CpuFeatures.Has(CpuFeatureAmd64SSE4_1)
	default:
		return false
	}
}

// MmapCodeSegment allocates and returns a byte slice to copy executable code into.
//
// See https://man7.org/linux/man-pages/man2/mmap.2.html for mmap API and flags.
func MmapCodeSegment(size int) ([]byte, error) {
	if size == 0 {
		panic("BUG: MmapCodeSegment with zero length")
	}
	return mmapCodeSegment(size)
}

// MunmapCodeSegment unmaps the given memory region.
func MunmapCodeSegment(code []byte) error {
	if len(code) == 0 {
		panic("BUG: MunmapCodeSegment with zero length")
	}
	return munmapCodeSegment(code)
}

func executableMmapSupported() bool {
	seg, err := MmapCodeSegment(1)
	if err != nil {
		return false
	}
	defer func() {
		_ = MunmapCodeSegment(seg)
	}()
	if err := MprotectCodeSegment(seg); err != nil {
		return false
	}
	return true
}
