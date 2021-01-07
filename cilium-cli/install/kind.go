// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package install

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"

	"github.com/cilium/cilium/pkg/versioncheck"
)

const kindMinVersionConstraint = ">=0.7.0"

var kindMinVersion = versioncheck.MustCompile(kindMinVersionConstraint)

type kindVersionValidation struct{}

func (m *kindVersionValidation) Name() string {
	return "minimum-version"
}

func (m *kindVersionValidation) Check(ctx context.Context, k *K8sInstaller) error {
	cmd := exec.Command("kind", "version")
	bytes, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("unable to execute \"kind version\": %w", err)
	}

	ver := regexp.MustCompile(`(v[0-9]+\.[0-9]+\.[0-9]+)`)
	verString := ver.FindString(string(bytes))
	v, err := versioncheck.Version(verString)
	if err != nil {
		return fmt.Errorf("unable to parse kind version %q: %w", verString, err)
	}

	if !kindMinVersion(v) {
		return fmt.Errorf("minimum version is %q, found version %q", kindMinVersionConstraint, v.String())
	}

	k.Log("✅ Detected kind version %q", v.String())

	return nil
}
