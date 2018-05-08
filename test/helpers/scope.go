package helpers

import (
	"fmt"
	"strings"

	ginkgoconfig "github.com/onsi/ginkgo/config"
)

// GetScope returns the scope for the currently running test.
func GetScope() string {
	focusString := strings.TrimSpace(strings.ToLower(ginkgoconfig.GinkgoConfig.FocusString))
	switch {
	case strings.HasPrefix(focusString, "run"):
		return Runtime
	case strings.HasPrefix(focusString, K8s):
		return K8s
	case strings.Contains(focusString, "nightly"):
		// Nightly tests run in a Kubernetes environment.
		return K8s
	default:
		return Runtime
	}
}

// GetScopeWithVersion returns the scope of the running test. If the scope is
// k8s, then it returns k8s scope along with the version of k8s that is running.
func GetScopeWithVersion() string {
	result := GetScope()
	if result != K8s {
		return result
	}
	return fmt.Sprintf("%s-%s", result, GetCurrentK8SEnv())
}
