// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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

	if ct.Params().Perf {
		if err := builder.NetworkPerformanceTests(ct); err != nil {
			return err
		}
		return ct.Run(ctx)
	}

	if ct.Params().IncludeConnDisruptTest {
		if err := builder.ConnDisruptTests(ct); err != nil {
			return err
		}
		if ct.Params().ConnDisruptTestSetup {
			// Exit early, as --conn-disrupt-test-setup is only needed to deploy pods which
			// will be used by another invocation of "cli connectivity test" (with
			// include --include-conn-disrupt-test"
			return ct.Run(ctx)
		}
	}

	if err := builder.ConcurrentTests(ct); err != nil {
		return err
	}

	if err := builder.SequentialTests(ct); err != nil {
		return err
	}

	if err := extra.AddConnectivityTests(ct); err != nil {
		return err
	}

	if err := builder.FinalTests(ct); err != nil {
		return err
	}

	return ct.Run(ctx)
}
