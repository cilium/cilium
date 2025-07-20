// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/cilium/cilium/cilium-cli/utils/features"
)

// Scenario is implemented by all test scenarios like pod-to-pod, pod-to-world, etc.
type Scenario interface {
	// Name returns the name of the Scenario.
	Name() string

	// Filepath returns the source code filename for the Scenario.
	FilePath() string

	// Run is invoked by the testing framework to execute the Scenario.
	Run(ctx context.Context, t *Test)
}

// ConditionalScenario is a test scenario which requires certain feature
// requirements to be enabled. If the requirements are not met, the test
// scenario is skipped
type ConditionalScenario interface {
	Scenario
	Requirements() []features.Requirement
}

type ScenarioBase struct {
	filepath string
}

func NewScenarioBase() ScenarioBase {
	return ScenarioBase{
		filepath: getSourceFile(),
	}
}

func (s ScenarioBase) FilePath() string {
	return s.filepath
}

// getSourceFile returns the file path for test scenario relative to the root
// of this repository.
func getSourceFile() string {
	// 2 steps up go to NewScenarioBase() => actual scenario constructor.
	_, path, _, ok := runtime.Caller(2)
	if ok {
		// 'path' is an absolute path on disk. Trim back to a relative
		// path from the root directory of the repository, calculated
		// using this filepath's relationship with the root directory.
		// If you move this logic, ensure that this calculation directs
		// back up to the root of the tree where CODEOWNERS exists!
		_, thisPath, _, _ := runtime.Caller(0)
		repoDir, _ := filepath.Abs(filepath.Join(thisPath, "..", "..", "..", ".."))
		return strings.TrimPrefix(path, repoDir+string(filepath.Separator))
	}
	// Fall back to the general owner of connectivity infrastructure.
	return "cilium-cli/connectivity/"
}
