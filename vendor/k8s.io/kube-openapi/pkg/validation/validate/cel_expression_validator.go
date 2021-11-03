// Copyright 2021 go-swagger maintainers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package validate

import (
	"fmt"
	"github.com/google/cel-go/cel"
	utilcel "k8s.io/kube-openapi/pkg/util/cel"
	"k8s.io/kube-openapi/pkg/validation/errors"
	"k8s.io/kube-openapi/pkg/validation/spec"
	"reflect"
)

func newCelExpressionValidator(path string, schema *spec.Schema) valueValidator {
	rules := &spec.ValidationRules{}
	err := schema.Extensions.GetObject("x-kubernetes-validations", rules)
	if err != nil {
		// The x-kubernetes-validations fields are validated at CRD registration time, so must be valid by the time they are used for validation
		panic(fmt.Sprintf("Unexpected error accessing x-kubernetes-validations at %s: %v", err, path))
	}
	if len(*rules) == 0 {
		return nil
	}
	programs, errs := utilcel.Compile(schema)
	if errs != nil {
		// Program complication is pre-checked at CRD creation/update time, so we don't expect compilation to fail here,
		// and it is an internal bug if they do.
		// But if somehow we get any compilation errors, we track them and then surface them as part of validation.
		return &celExpressionValidator{Path: path, Schema: schema, CompileErrors: errs}
	}
	return &celExpressionValidator{Path: path, Schema: schema, Rules: *rules, Programs: programs}
}

type celExpressionValidator struct {
	Path          string
	Schema        *spec.Schema
	CompileErrors []error
	Rules         spec.ValidationRules
	Programs      []cel.Program
}

func (c *celExpressionValidator) SetPath(path string) {
	c.Path = path
}

func (c *celExpressionValidator) Applies(source interface{}, _ reflect.Kind) bool {
	switch source.(type) {
	case *spec.Schema:
		return true
	}
	return false
}

func (c *celExpressionValidator) Validate(data interface{}) *Result {
	res := new(Result)
	if len(c.CompileErrors) > 0 {
		// Program complication is pre-checked at CRD creation/update time, so it is an internal bug if compilation errors to make it this far.
		// But if somehow we get any, we surface them here as validation errors.
		for _, e := range c.CompileErrors {
			res.AddErrors(errors.ErrorExecutingValidatorRule(c.Path, "", "<compilation phase>", e, data))
		}
	}
	for i, program := range c.Programs {
		rule := c.Rules[i]

		vars := map[string]interface{}{}
		if obj, ok := data.(map[string]interface{}); ok {
			for k, v := range obj {
				vars[k] = v
			}
		}
		vars[utilcel.ScopedVarName] = data
		evalResult, _, err := program.Eval(vars)
		if err != nil {
			res.AddErrors(errors.ErrorExecutingValidatorRule(c.Path, "", rule.Rule, err, data))
			continue
		}
		if evalResult.Value() != true {
			res.AddErrors(errors.FailedValidatorRule(c.Path, "", rule.Rule, rule.Message, data))
		}
	}
	return res
}
