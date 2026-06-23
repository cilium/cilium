// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connectivity

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/cilium/cilium-cli/connectivity/builder"
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/runner"
)

// Hooks defines the extension hooks provided by connectivity tests.
type Hooks interface {
	check.SetupHooks
	// AddConnectivityTests is an hook to register additional connectivity tests.
	AddConnectivityTests(cts ...*check.ConnectivityTest) error
}

func Run(ctx context.Context, connTests []*check.ConnectivityTest, extra Hooks) (err error) {
	// If cleanup-only mode is enabled, perform cleanup and return
	if len(connTests) > 0 && connTests[0].Params().CleanupOnly {
		connTests[0].Infof("🧹 Cleanup mode enabled - removing all connectivity test artifacts")
		for i := range connTests {
			if e := connTests[i].CleanupConnectivityTest(ctx); e != nil {
				connTests[i].Warnf("Cleanup encountered errors: %v", e)
			}
		}
		connTests[0].Infof("✅ Cleanup complete")
		return nil
	}

	var (
		junitCollector *check.JUnitCollector
		junitWritten   bool
	)
	if len(connTests) > 0 && connTests[0].Params().JunitFile != "" {
		junitCollector = check.NewJUnitCollector(connTests[0].Params().JunitProperties, connTests[0].Params().JunitFile, connTests[0].CodeOwners)
		defer func() {
			if err == nil || junitWritten || junitCollector == nil {
				return
			}
			if len(connTests) == 0 || connTests[0] == nil {
				return
			}
			err = writeInfrastructureJUnit(junitCollector, connTests[0], err)
		}()
	}

	if err = setupConnectivityTests(ctx, connTests, extra); err != nil {
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
		for j := range connTests {
			if e := connTests[j].SetupStaticRoutes(ctx); e != nil {
				return e
			}
		}
		runErr := runConnectivityTests(ctx, connTests)
		if runErr != nil {
			return runErr
		}
		for j := range connTests {
			if junitCollector != nil {
				junitCollector.Collect(connTests[j])
			}
			if e := connTests[j].PrintReport(ctx); e != nil {
				err = errors.Join(err, e)
			}
			connTests[j].Cleanup()
		}
		for j := range connTests {
			if e := connTests[j].TeardownStaticRoutes(ctx); e != nil {
				err = errors.Join(err, e)
			}
		}
	}

	if junitCollector != nil {
		if werr := junitCollector.Write(); werr != nil {
			if len(connTests) > 0 && connTests[0] != nil {
				connTests[0].Failf("writing to junit file %s failed: %s", connTests[0].Params().JunitFile, werr)
			}
			err = errors.Join(err, fmt.Errorf("writing junit report: %w", werr))
		} else {
			junitWritten = true
		}
	}
	return err
}

func writeInfrastructureJUnit(collector *check.JUnitCollector, ct *check.ConnectivityTest, failure error) error {
	if failure == nil {
		return nil
	}
	if collector == nil || ct == nil {
		return failure
	}

	collector.RecordInfrastructureFailure(failure)
	if werr := collector.Write(); werr != nil {
		ct.Failf("writing to junit file %s failed: %s", ct.Params().JunitFile, werr)
		return errors.Join(failure, fmt.Errorf("writing junit report: %w", werr))
	}
	return failure
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
	for i := range connTests {
		if !finish[i] {
			// Exit with a non-zero return code.
			return errors.New("encountered internal error, exiting")
		}
	}
	return nil
}
