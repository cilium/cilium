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

package types

import (
	"context"
	"testing"

	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

// EnvFunc represents a user-defined operation that
// can be used to customized the behavior of the
// environment. Changes to context are expected to surface
// to caller.
type EnvFunc func(context.Context, *envconf.Config) (context.Context, error)

// FeatureEnvFunc represents a user-defined operation that
// can be used to customized the behavior of the
// environment. Changes to context are expected to surface
// to caller. Meant for use with before/after feature hooks.
// *testing.T is provided in order to provide pass/fail context to
// features.
type FeatureEnvFunc func(context.Context, *envconf.Config, *testing.T, Feature) (context.Context, error)

// TestEnvFunc represents a user-defined operation that
// can be used to customized the behavior of the
// environment. Changes to context are expected to surface
// to caller. Meant for use with before/after test hooks.
type TestEnvFunc func(context.Context, *envconf.Config, *testing.T) (context.Context, error)

// Environment represents an environment where
// features can be tested.
type Environment interface {
	// WithContext returns a new Environment with a new context
	WithContext(context.Context) Environment

	// Setup registers environment operations that are executed once
	// prior to the environment being ready and prior to any test.
	Setup(...EnvFunc) Environment

	// BeforeEachTest registers environment funcs that are executed
	// before each Env.Test(...)
	BeforeEachTest(...TestEnvFunc) Environment

	// BeforeEachFeature registers step functions that are executed
	// before each Feature is tested during env.Test call.
	BeforeEachFeature(...FeatureEnvFunc) Environment

	// AfterEachFeature registers step functions that are executed
	// after each feature is tested during an env.Test call.
	AfterEachFeature(...FeatureEnvFunc) Environment

	// Test executes a test feature defined in a TestXXX function
	// This method surfaces context for further updates.
	Test(*testing.T, ...Feature)

	// TestInParallel executes a series of test features defined in a
	// TestXXX function in parallel. This works the same way Test method
	// does with the caveat that the features will all be run in parallel
	TestInParallel(*testing.T, ...Feature)

	// AfterEachTest registers environment funcs that are executed
	// after each Env.Test(...).
	AfterEachTest(...TestEnvFunc) Environment

	// Finish registers funcs that are executed at the end of the
	// test suite.
	Finish(...EnvFunc) Environment

	// Run Launches the test suite from within a TestMain
	Run(*testing.M) int
}

type Labels map[string]string

type Feature interface {
	// Name is a descriptive text for the feature
	Name() string
	// Labels returns a map of feature labels
	Labels() Labels
	// Steps testing tasks to test the feature
	Steps() []Step
}

type Level uint8

const (
	// LevelSetup when doing the setup phase
	LevelSetup Level = iota
	// LevelAssess when doing the assess phase
	LevelAssess
	// LevelTeardown when doing the teardown phase
	LevelTeardown
)

type StepFunc func(context.Context, *testing.T, *envconf.Config) context.Context

type Step interface {
	// Name is the step name
	Name() string
	// Level action level {setup|requirement|assertion|teardown}
	Level() Level
	// Func is the operation for the step
	Func() StepFunc
}
