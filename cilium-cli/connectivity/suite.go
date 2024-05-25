// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connectivity

import (
	"context"
	"errors"

	"github.com/cilium/cilium-cli/connectivity/builder"
	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/utils/runner"
)

// Hooks defines the extension hooks provided by connectivity tests.
type Hooks interface {
	check.SetupHooks
	// AddConnectivityTests is an hook to register additional connectivity tests.
	AddConnectivityTests(ct *check.ConnectivityTest) error
}

func Run(ctx context.Context, connTests []*check.ConnectivityTest, extra Hooks) error {
	if err := setupConnectivityTests(ctx, connTests, extra); err != nil {
		return err
	}

	connTests[0].Infof("Cilium version: %v", connTests[0].CiliumVersion)

	suiteBuilders, err := builder.GetTestSuites(connTests[0].Params())
	if err != nil {
		return err
	}
	for i := range suiteBuilders {
		if e := suiteBuilders[i](connTests, extra.AddConnectivityTests); e != nil {
			return e
		}
		for j := range connTests {
			connTests[j].PrintTestInfo()
		}
		if e := runConnectivityTests(ctx, connTests); e != nil {
			return e
		}
		for j := range connTests {
			if e := connTests[j].PrintReport(ctx); e != nil {
				err = errors.Join(err, e)
			}
			connTests[j].Cleanup()
		}
	}
	return err
}

func setupConnectivityTests(ctx context.Context, connTest []*check.ConnectivityTest, hooks Hooks) error {
	me := runner.MultiError{}
	for i := range connTest {
		id := i
		me.Go(func() error {
			return connTest[id].SetupAndValidate(ctx, hooks)
		})
	}
	return me.Wait()
}

func runConnectivityTests(ctx context.Context, connTests []*check.ConnectivityTest) error {
	finish := make([]bool, len(connTests))
	me := runner.MultiError{}
	for i := range connTests {
		id := i
		// Execute connectivity.Run() in its own goroutine, it might call Fatal()
		// and end the goroutine without returning.
		me.Go(func() error {
			err := connTests[id].Run(ctx)
			// If Fatal() was called in the test suite, the statement below won't fire.
			finish[id] = true
			return err
		})
	}
	if err := me.Wait(); err != nil {
		return err
	}
	for i := 0; i < len(connTests); i++ {
		if !finish[i] {
			// Exit with a non-zero return code.
			return errors.New("encountered internal error, exiting")
		}
	}
	return nil
}
