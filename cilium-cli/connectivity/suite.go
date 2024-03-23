// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package connectivity defines tests executed by the "cilium connectivity test"
// command. Do not modify this package. It's being moved to cilium/cilium repo as
// a part of https://github.com/cilium/design-cfps/pull/9.
package connectivity

import (
	"context"

	"github.com/cilium/cilium-cli/connectivity/builder"
	"github.com/cilium/cilium-cli/connectivity/check"
)

// Hooks defines the extension hooks provided by connectivity tests.
type Hooks interface {
	check.SetupHooks
	// AddConnectivityTests is an hook to register additional connectivity tests.
	AddConnectivityTests(ct *check.ConnectivityTest) error
}

func Run(ctx context.Context, ct *check.ConnectivityTest, extra Hooks) error {
	if err := ct.SetupAndValidate(ctx, extra); err != nil {
		return err
	}

	ct.Infof("Cilium version: %v", ct.CiliumVersion)

	extraTests := func(ct *check.ConnectivityTest) error { return extra.AddConnectivityTests(ct) }
	if err := builder.InjectTests(ct, extraTests); err != nil {
		return err
	}

	return ct.Run(ctx)
}
