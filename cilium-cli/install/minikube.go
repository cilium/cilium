// Copyright 2020 Authors of Cilium
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
	"regexp"

	"github.com/cilium/cilium/pkg/versioncheck"
)

const minikubeMinVersionConstraint = ">=1.5.2"

var minikubeMinVersion = versioncheck.MustCompile(minikubeMinVersionConstraint)

type minikubeVersionValidation struct{}

func (m *minikubeVersionValidation) Name() string {
	return "minimum-version"
}

func (m *minikubeVersionValidation) Check(ctx context.Context, k *K8sInstaller) error {
	bytes, err := k.Exec("minikube", "version")
	if err != nil {
		return err
	}

	ver := regexp.MustCompile(`(v[0-9]+\.[0-9]+\.[0-9]+)`)
	verString := ver.FindString(string(bytes))
	v, err := versioncheck.Version(verString)
	if err != nil {
		return fmt.Errorf("unable to parse minikube version %q: %w", verString, err)
	}

	if !minikubeMinVersion(v) {
		return fmt.Errorf("minimum version is %q, found version %q", minikubeMinVersionConstraint, v.String())
	}

	k.Log("✅ Detected minikube version %q", v.String())

	return nil
}
