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

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/k8s"
)

type validationCheck interface {
	Name() string
	Check(ctx context.Context, k *K8sInstaller) error
}

var (
	validationChecks = map[k8s.Kind][]validationCheck{
		k8s.KindMinikube: []validationCheck{
			&minikubeVersionValidation{},
		},
		k8s.KindKind: []validationCheck{
			&kindVersionValidation{},
		},
	}
)

func (p InstallParameters) checkDisabled(name string) bool {
	for _, n := range p.DisableChecks {
		if n == name {
			return true
		}
	}
	return false
}

func (k *K8sUninstaller) autodetect(ctx context.Context) error {
	f, err := k.client.AutodetectFlavor(ctx)
	if err != nil {
		return err
	}

	k.flavor = f

	if f.Kind != k8s.KindUnknown {
		k.Log("🔮 Auto-detected Kubernetes kind: %s", f.Kind)
	}

	return nil
}

func (k *K8sInstaller) autodetectAndValidate(ctx context.Context) error {
	f, err := k.client.AutodetectFlavor(ctx)
	if err != nil {
		return err
	}

	k.flavor = f

	if f.Kind != k8s.KindUnknown {
		k.Log("🔮 Auto-detected Kubernetes kind: %s", f.Kind)
	}

	if len(validationChecks[k.flavor.Kind]) > 0 {
		k.Log("✨ Running %q validation checks", f.Kind)
		for _, check := range validationChecks[f.Kind] {
			name := check.Name()
			if k.params.checkDisabled(name) {
				k.Log("⏭️  Skipping disabled validtion test %q", name)
				continue
			}

			if err := check.Check(ctx, k); err != nil {
				k.Log("❌ Validation test %s failed: %s", name, err)
				k.Log("ℹ️  You can disable the test with --disable-check=%s", name)
				return fmt.Errorf("validation check for kind %q failed: %w", f.Kind, err)
			}
		}
	}

	if k.params.Version == "" {
		k.Log("ℹ️  Cilium version not set, using default version %q", defaults.Version)
		k.params.Version = defaults.Version
	}

	if k.params.ClusterName == "" {
		if f.ClusterName != "" {
			k.Log("🔮 Auto-detected cluster name: %s", f.ClusterName)
			k.params.ClusterName = f.ClusterName
		}
	}

	if k.params.DatapathMode == "" {
		switch f.Kind {
		case k8s.KindMinikube:
			k.params.DatapathMode = DatapathTunnel
		case k8s.KindEKS:
			k.params.DatapathMode = DatapathAwsENI
		}

		if k.params.DatapathMode != "" {
			k.Log("🔮 Auto-detected datapath mode: %s", k.params.DatapathMode)
		}
	}

	return nil
}
