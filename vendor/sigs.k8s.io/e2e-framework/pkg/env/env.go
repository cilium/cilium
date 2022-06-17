/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package env exposes types to create type `Environment` used to run
// feature tests.
package env

import (
	"context"
	"fmt"
	"math/rand"
	"regexp"
	"sync"
	"testing"
	"time"

	"k8s.io/klog/v2"

	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/internal/types"
)

type (
	Environment = types.Environment
	Func        = types.EnvFunc
	FeatureFunc = types.FeatureEnvFunc

	actionRole uint8
)

type testEnv struct {
	ctx     context.Context
	cfg     *envconf.Config
	actions []action
	rnd     rand.Source
}

// New creates a test environment with no config attached.
func New() types.Environment {
	return newTestEnv()
}

func NewParallel() types.Environment {
	return newTestEnvWithParallel()
}

// NewWithConfig creates an environment using an Environment Configuration value
func NewWithConfig(cfg *envconf.Config) types.Environment {
	env := newTestEnv()
	env.cfg = cfg
	return env
}

// NewWithKubeConfig creates an environment using an Environment Configuration value
// and the given kubeconfig.
func NewWithKubeConfig(kubeconfigfile string) types.Environment {
	env := newTestEnv()
	cfg := envconf.NewWithKubeConfig(kubeconfigfile)
	env.cfg = cfg
	return env
}

// NewInClusterConfig creates an environment using an Environment Configuration value
// and assumes an in-cluster kubeconfig.
func NewInClusterConfig() types.Environment {
	env := newTestEnv()
	cfg := envconf.NewWithKubeConfig("")
	env.cfg = cfg
	return env
}

// NewWithContext creates a new environment with the provided context and config.
func NewWithContext(ctx context.Context, cfg *envconf.Config) (types.Environment, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is nil")
	}
	if cfg == nil {
		return nil, fmt.Errorf("environment config is nil")
	}
	return &testEnv{ctx: ctx, cfg: cfg}, nil
}

func newTestEnv() *testEnv {
	return &testEnv{
		ctx: context.Background(),
		cfg: envconf.New(),
		rnd: rand.NewSource(time.Now().UnixNano()),
	}
}

func newTestEnvWithParallel() *testEnv {
	return &testEnv{
		ctx: context.Background(),
		cfg: envconf.New().WithParallelTestEnabled(),
	}
}

// WithContext returns a new environment with the context set to ctx.
// Argument ctx cannot be nil
func (e *testEnv) WithContext(ctx context.Context) types.Environment {
	if ctx == nil {
		panic("nil context") // this should never happen
	}
	env := &testEnv{
		ctx: ctx,
		cfg: e.cfg,
	}
	env.actions = append(env.actions, e.actions...)
	return env
}

// Setup registers environment operations that are executed once
// prior to the environment being ready and prior to any test.
func (e *testEnv) Setup(funcs ...Func) types.Environment {
	if len(funcs) == 0 {
		return e
	}
	e.actions = append(e.actions, action{role: roleSetup, funcs: funcs})
	return e
}

// BeforeEachTest registers environment funcs that are executed
// before each Env.Test(...)
func (e *testEnv) BeforeEachTest(funcs ...types.TestEnvFunc) types.Environment {
	if len(funcs) == 0 {
		return e
	}
	e.actions = append(e.actions, action{role: roleBeforeTest, testFuncs: funcs})
	return e
}

// BeforeEachFeature registers step functions that are executed
// before each Feature is tested during env.Test call.
func (e *testEnv) BeforeEachFeature(funcs ...FeatureFunc) types.Environment {
	if len(funcs) == 0 {
		return e
	}
	e.actions = append(e.actions, action{role: roleBeforeFeature, featureFuncs: funcs})
	return e
}

// AfterEachFeature registers step functions that are executed
// after each feature is tested during an env.Test call.
func (e *testEnv) AfterEachFeature(funcs ...FeatureFunc) types.Environment {
	if len(funcs) == 0 {
		return e
	}
	e.actions = append(e.actions, action{role: roleAfterFeature, featureFuncs: funcs})
	return e
}

// AfterEachTest registers environment funcs that are executed
// after each Env.Test(...).
func (e *testEnv) AfterEachTest(funcs ...types.TestEnvFunc) types.Environment {
	if len(funcs) == 0 {
		return e
	}
	e.actions = append(e.actions, action{role: roleAfterTest, testFuncs: funcs})
	return e
}

// panicOnMissingContext is used to check if the test Env has a non-nil context setup
// and fail fast if the context has not already been set
func (e *testEnv) panicOnMissingContext() {
	if e.ctx == nil {
		panic("context not set") // something is terribly wrong.
	}
}

// processTestActions is used to run a series of test action that were configured as
// BeforeEachTest or AfterEachTest
func (e *testEnv) processTestActions(t *testing.T, actions []action) {
	var err error
	for _, action := range actions {
		if e.ctx, err = action.runWithT(e.ctx, e.cfg, t); err != nil {
			t.Fatalf("BeforeEachTest failure: %s", err)
		}
	}
}

// processTestFeature is used to trigger the execution of the actual feature. This function wraps the entire
// workflow of orchestrating the feature execution be running the action configured by BeforeEachFeature /
// AfterEachFeature.
func (e *testEnv) processTestFeature(t *testing.T, featureName string, feature types.Feature) {
	var err error

	// execute each feature
	beforeFeatureActions := e.getBeforeFeatureActions()
	afterFeatureActions := e.getAfterFeatureActions()

	for _, action := range beforeFeatureActions {
		if e.ctx, err = action.runWithFeature(e.ctx, e.cfg, t, deepCopyFeature(feature)); err != nil {
			t.Fatalf("BeforeEachTest failure: %s", err)
		}
	}

	// execute feature test
	e.ctx = e.execFeature(e.ctx, t, featureName, feature)

	// execute beforeFeature actions
	for _, action := range afterFeatureActions {
		if e.ctx, err = action.runWithFeature(e.ctx, e.cfg, t, deepCopyFeature(feature)); err != nil {
			t.Fatalf("BeforeEachTest failure: %s", err)
		}
	}
}

// processTests is a wrapper function that can be invoked by either Test or TestInParallel methods.
// Depending on the configuration of if the parallel tests are enabled or not, this will change the
// nature of how the test gets executed.
//
// In case if the parallel run of test features are enabled, this function will invoke the processTestFeature
// as a go-routine to get them to run in parallel
func (e *testEnv) processTests(t *testing.T, enableParallelRun bool, testFeatures ...types.Feature) {
	if e.cfg.DryRunMode() {
		klog.V(2).Info("e2e-framework is being run in dry-run mode. This will skip all the before/after step functions configured around your test assessments and features")
	}
	e.panicOnMissingContext()
	if len(testFeatures) == 0 {
		t.Log("No test testFeatures provided, skipping test")
		return
	}
	beforeTestActions := e.getBeforeTestActions()
	afterTestActions := e.getAfterTestActions()

	e.processTestActions(t, beforeTestActions)

	runInParallel := e.cfg.ParallelTestEnabled() && enableParallelRun

	if runInParallel {
		klog.V(4).Info("Running test features in parallel")
	}

	var wg sync.WaitGroup
	for i, feature := range testFeatures {
		featureCopy := feature
		featName := feature.Name()
		if featName == "" {
			featName = fmt.Sprintf("Feature-%d", i+1)
		}
		if runInParallel {
			wg.Add(1)
			go func(w *sync.WaitGroup, featName string, f types.Feature) {
				defer w.Done()
				e.processTestFeature(t, featName, f)
			}(&wg, featName, featureCopy)
		} else {
			e.processTestFeature(t, featName, featureCopy)
			// In case if the feature under test has failed, skip reset of the features
			// that are part of the same test
			if e.cfg.FailFast() && t.Failed() {
				break
			}
		}
	}
	if runInParallel {
		wg.Wait()
	}
	e.processTestActions(t, afterTestActions)
}

// TestInParallel executes a series a feature tests from within a
// TestXXX function in parallel
//
// Feature setups and teardowns are executed at the same *testing.T
// contextual level as the "test" that invoked this method. Assessments
// are executed as a subtests of the feature.  This approach allows
// features/assessments to be filtered using go test -run flag.
//
// Feature tests will have access to and able to update the context
// passed to it.
//
// BeforeTest and AfterTest operations are executed before and after
// the feature is tested respectively.
//
// BeforeTest and AfterTest operations are run in series of the entire
// set of features being passed to this call while the feature themselves
// are executed in parallel to avoid duplication of action that might happen
// in BeforeTest and AfterTest actions
func (e *testEnv) TestInParallel(t *testing.T, testFeatures ...types.Feature) {
	e.processTests(t, true, testFeatures...)
}

// Test executes a feature test from within a TestXXX function.
//
// Feature setups and teardowns are executed at the same *testing.T
// contextual level as the "test" that invoked this method. Assessments
// are executed as a subtests of the feature.  This approach allows
// features/assessments to be filtered using go test -run flag.
//
// Feature tests will have access to and able to update the context
// passed to it.
//
// BeforeTest and AfterTest operations are executed before and after
// the feature is tested respectively.
func (e *testEnv) Test(t *testing.T, testFeatures ...types.Feature) {
	e.processTests(t, false, testFeatures...)
}

// Finish registers funcs that are executed at the end of the
// test suite.
func (e *testEnv) Finish(funcs ...Func) types.Environment {
	if len(funcs) == 0 {
		return e
	}

	e.actions = append(e.actions, action{role: roleFinish, funcs: funcs})
	return e
}

// Run is to launch the test suite from a TestMain function.
// It will run m.Run() and exercise all test functions in the
// package.  This method will all Env.Setup operations prior to
// starting the tests and run all Env.Finish operations after
// before completing the suite.
//
func (e *testEnv) Run(m *testing.M) int {
	if e.ctx == nil {
		panic("context not set") // something is terribly wrong.
	}

	setups := e.getSetupActions()
	// fail fast on setup, upon err exit
	var err error
	for _, setup := range setups {
		// context passed down to each setup
		if e.ctx, err = setup.run(e.ctx, e.cfg); err != nil {
			klog.Fatal(err)
		}
	}

	exitCode := m.Run() // exec test suite

	finishes := e.getFinishActions()
	// attempt to gracefully clean up.
	// Upon error, log and continue.
	for _, fin := range finishes {
		// context passed down to each finish step
		if e.ctx, err = fin.run(e.ctx, e.cfg); err != nil {
			klog.V(2).ErrorS(err, "Finish action handlers")
		}
	}

	return exitCode
}

func (e *testEnv) getActionsByRole(r actionRole) []action {
	if e.actions == nil {
		return nil
	}

	var result []action
	for _, a := range e.actions {
		if a.role == r {
			result = append(result, a)
		}
	}

	return result
}

func (e *testEnv) getSetupActions() []action {
	return e.getActionsByRole(roleSetup)
}

func (e *testEnv) getBeforeTestActions() []action {
	return e.getActionsByRole(roleBeforeTest)
}

func (e *testEnv) getBeforeFeatureActions() []action {
	return e.getActionsByRole(roleBeforeFeature)
}

func (e *testEnv) getAfterFeatureActions() []action {
	return e.getActionsByRole(roleAfterFeature)
}

func (e *testEnv) getAfterTestActions() []action {
	return e.getActionsByRole(roleAfterTest)
}

func (e *testEnv) getFinishActions() []action {
	return e.getActionsByRole(roleFinish)
}

func (e *testEnv) executeSteps(ctx context.Context, t *testing.T, steps []types.Step) context.Context {
	if e.cfg.DryRunMode() {
		return ctx
	}
	for _, setup := range steps {
		ctx = setup.Func()(ctx, t, e.cfg)
	}
	return ctx
}

func (e *testEnv) execFeature(ctx context.Context, t *testing.T, featName string, f types.Feature) context.Context {
	// feature-level subtest
	t.Run(featName, func(t *testing.T) {
		skipped, message := e.requireFeatureProcessing(f)
		if skipped {
			t.Skipf(message)
		}

		// setups run at feature-level
		setups := features.GetStepsByLevel(f.Steps(), types.LevelSetup)
		ctx = e.executeSteps(ctx, t, setups)

		// assessments run as feature/assessment sub level
		assessments := features.GetStepsByLevel(f.Steps(), types.LevelAssess)

		failed := false
		for i, assess := range assessments {
			assessName := assess.Name()
			if assessName == "" {
				assessName = fmt.Sprintf("Assessment-%d", i+1)
			}
			t.Run(assessName, func(t *testing.T) {
				skipped, message := e.requireAssessmentProcessing(assess, i+1)
				if skipped {
					t.Skipf(message)
				}
				ctx = e.executeSteps(ctx, t, []types.Step{assess})
			})
			// Check if the Test assessment under question performed a `t.Fail()` or `t.Failed()` invocation.
			// We need to track that and stop the next set of assessment in the feature under test from getting
			// executed
			if e.cfg.FailFast() && t.Failed() {
				failed = true
				break
			}
		}

		// Let us fail the test fast and not run the teardown in case if the framework specific fail-fast mode is
		// invoked to make sure we leave the traces of the failed test behind to enable better debugging for the
		// test developers
		if e.cfg.FailFast() && failed {
			t.FailNow()
		}

		// teardowns run at feature-level
		teardowns := features.GetStepsByLevel(f.Steps(), types.LevelTeardown)
		ctx = e.executeSteps(ctx, t, teardowns)
	})

	return ctx
}

// requireFeatureProcessing is a wrapper around the requireProcessing function to process the feature level validation
func (e *testEnv) requireFeatureProcessing(f types.Feature) (skip bool, message string) {
	requiredRegexp := e.cfg.FeatureRegex()
	skipRegexp := e.cfg.SkipFeatureRegex()
	return e.requireProcessing("feature", f.Name(), requiredRegexp, skipRegexp, f.Labels())
}

// requireAssessmentProcessing is a wrapper around the requireProcessing function to process the Assessment level validation
func (e *testEnv) requireAssessmentProcessing(a types.Step, assessmentIndex int) (skip bool, message string) {
	requiredRegexp := e.cfg.AssessmentRegex()
	skipRegexp := e.cfg.SkipAssessmentRegex()
	assessmentName := a.Name()
	if assessmentName == "" {
		assessmentName = fmt.Sprintf("Assessment-%d", assessmentIndex)
	}
	return e.requireProcessing("assessment", assessmentName, requiredRegexp, skipRegexp, nil)
}

// requireProcessing is a utility function that can be used to make a decision on if a specific Test assessment or feature needs to be
// processed or not.
// testName argument indicate the Feature Name or test Name that can be mapped against the skip or include regex flags
// to decide if the entity in question will need processing.
// This function also perform a label check against include/skip labels to make sure only those features to make sure
// we can filter out all the non-required features during the test execution
func (e *testEnv) requireProcessing(kind, testName string, requiredRegexp, skipRegexp *regexp.Regexp, labels types.Labels) (skip bool, message string) {
	if requiredRegexp != nil && !requiredRegexp.MatchString(testName) {
		skip = true
		message = fmt.Sprintf(`Skipping %s "%s": name not matched`, kind, testName)
		return skip, message
	}
	if skipRegexp != nil && skipRegexp.MatchString(testName) {
		skip = true
		message = fmt.Sprintf(`Skipping %s: "%s": name matched`, kind, testName)
		return skip, message
	}

	if labels != nil {
		for k, v := range e.cfg.Labels() {
			if labels[k] != v {
				skip = true
				message = fmt.Sprintf(`Skipping feature "%s": unmatched label "%s=%s"`, testName, k, labels[k])
				return skip, message
			}
		}

		// skip running a feature if labels matches with --skip-labels
		for k, v := range e.cfg.SkipLabels() {
			if labels[k] == v {
				skip = true
				message = fmt.Sprintf(`Skipping feature "%s": matched label provided in --skip-lables "%s=%s"`, testName, k, labels[k])
				return skip, message
			}
		}
	}
	return skip, message
}

// deepCopyFeature just copies the values from the Feature but creates a deep
// copy to avoid mutation when we just want an informational copy.
func deepCopyFeature(f types.Feature) types.Feature {
	fcopy := features.New(f.Name())
	for k, v := range f.Labels() {
		fcopy = fcopy.WithLabel(k, v)
	}
	f.Steps()
	for _, step := range f.Steps() {
		fcopy = fcopy.WithStep(step.Name(), step.Level(), nil)
	}
	return fcopy.Feature()
}
