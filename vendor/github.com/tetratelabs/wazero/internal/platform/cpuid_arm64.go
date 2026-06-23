package platform

import "golang.org/x/sys/cpu"

// CpuFeatures exposes the capabilities for this CPU, queried via the Has method.
var CpuFeatures = loadCpuFeatureFlags()

func loadCpuFeatureFlags() (flags CpuFeatureFlags) {
	if cpu.ARM64.HasATOMICS {
		flags |= CpuFeatureArm64Atomic
	}
	return
}
