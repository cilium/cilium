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
	"fmt"

	"sigs.k8s.io/e2e-framework/pkg/internal/types"
)

// FeatureBuilder represents is a type to define a
// testable feature
type FeatureBuilder struct {
	feat *defaultFeature
}

func New(name string) *FeatureBuilder {
	return &FeatureBuilder{feat: newDefaultFeature(name)}
}

// WithLabel adds a test label key/value pair
func (b *FeatureBuilder) WithLabel(key, value string) *FeatureBuilder {
	b.feat.labels[key] = value
	return b
}

// WithStep adds a new step that will be applied prior to feature test.
func (b *FeatureBuilder) WithStep(name string, level Level, fn Func) *FeatureBuilder {
	b.feat.steps = append(b.feat.steps, newStep(name, level, fn))
	return b
}

// Setup adds a new setup step that will be applied prior to feature test.
func (b *FeatureBuilder) Setup(fn Func) *FeatureBuilder {
	return b.WithSetup(fmt.Sprintf("%s-setup", b.feat.name), fn)
}

// WithSetup adds a new setup step with a pre-defined setup name instead of automating
// the setup name generation. This can make tests more readable.
func (b *FeatureBuilder) WithSetup(name string, fn Func) *FeatureBuilder {
	return b.WithStep(name, types.LevelSetup, fn)
}

// Teardown adds a new teardown step that will be applied after feature test.
func (b *FeatureBuilder) Teardown(fn Func) *FeatureBuilder {
	return b.WithTeardown(fmt.Sprintf("%s-teardown", b.feat.name), fn)
}

// WithTeardown adds a new teardown step with a pre-defined name instead of an
// auto-generated one
func (b *FeatureBuilder) WithTeardown(name string, fn Func) *FeatureBuilder {
	return b.WithStep(name, types.LevelTeardown, fn)
}

// Assess adds an assessment step to the feature test.
func (b *FeatureBuilder) Assess(desc string, fn Func) *FeatureBuilder {
	return b.WithStep(desc, types.LevelAssess, fn)
}

// Feature returns a feature configured by builder.
func (b *FeatureBuilder) Feature() types.Feature {
	return b.feat
}
