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

package features

import (
	"regexp"

	"sigs.k8s.io/e2e-framework/pkg/internal/types"
)

type (
	Labels  = types.Labels
	Feature = types.Feature
	Step    = types.Step
	Func    = types.StepFunc
	Level   = types.Level
)

type defaultFeature struct {
	name   string
	labels types.Labels
	steps  []types.Step
}

func newDefaultFeature(name string) *defaultFeature {
	return &defaultFeature{name: name, labels: make(types.Labels)}
}

func (f *defaultFeature) Name() string {
	return f.name
}

func (f *defaultFeature) Labels() types.Labels {
	return f.labels
}

func (f *defaultFeature) Steps() []types.Step {
	return f.steps
}

type testStep struct {
	name  string
	level Level
	fn    Func
}

func newStep(name string, level Level, fn Func) *testStep {
	return &testStep{
		name:  name,
		level: level,
		fn:    fn,
	}
}

func (s *testStep) Name() string {
	return s.name
}

func (s *testStep) Level() Level {
	return s.level
}

func (s *testStep) Func() Func {
	return s.fn
}

func GetStepsByLevel(steps []types.Step, l types.Level) []types.Step {
	if steps == nil {
		return nil
	}
	var result []Step
	for _, s := range steps {
		if s.Level() == l {
			result = append(result, s)
		}
	}

	return result
}

func FilterStepsByName(steps []types.Step, regexName *regexp.Regexp) []types.Step {
	if steps == nil {
		return nil
	}
	var result []Step
	for _, s := range steps {
		if regexName.MatchString(s.Name()) {
			result = append(result, s)
		}
	}

	return result
}
