// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package install

import (
	"context"
	"fmt"
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
	bytes, err := k.Exec("kind", "version")
	if err != nil {
		return err
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
