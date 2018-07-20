package helpers

import (
	"errors"
	"fmt"
	"strings"

	ginkgoconfig "github.com/onsi/ginkgo/config"
)

// PreDefinedScope in case that the test scope is defined by the user instead
// of the focus string.
var PreDefinedScope string

// GetScope returns the scope for the currently running test.
func GetScope() (string, error) {
	if PreDefinedScope != "" {
		return PreDefinedScope, nil
	}

	focusString := strings.TrimSpace(strings.ToLower(ginkgoconfig.GinkgoConfig.FocusString))
	switch {
	case strings.HasPrefix(focusString, "run"):
		return Runtime, nil
	case strings.HasPrefix(focusString, K8s):
		return K8s, nil
	case strings.Contains(focusString, "nightly"):
		// Nightly tests run in a Kubernetes environment.
		return K8s, nil
	default:
		return "", errors.New("Scope cannot be set")
	}
}

// GetScopeWithVersion returns the scope of the running test. If the scope is
// k8s, then it returns k8s scope along with the version of k8s that is running.
func GetScopeWithVersion() string {
	result, _ := GetScope()
	if result != K8s {
		return result
	}
	return fmt.Sprintf("%s-%s", result, GetCurrentK8SEnv())
}
