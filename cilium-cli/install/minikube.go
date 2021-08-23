// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

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
