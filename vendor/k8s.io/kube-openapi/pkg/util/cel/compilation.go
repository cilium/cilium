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

package cel

import (
	"fmt"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"k8s.io/kube-openapi/pkg/validation/spec"
	celmodel "k8s.io/kube-openapi/third_party/forked/celopenapi/model"
)

// ScopedTypeName is the placeholder type name used for the type of ScopedVarName if it is an object type.
const ScopedTypeName = "SelfSchemaType.expressionlanguage.k8s.io"

// ScopedVarName is the variable name assigned to the locally scoped data element of a CEL rule.
const ScopedVarName = "self"

// Compile compiles all the CEL validation rules in the CelRules and returns a slice containing a compiled program for each provided CelRule, or an array of errors.
func Compile(schema *spec.Schema) ([]cel.Program, []error) {
	var allErrors []error
	celRules := &spec.ValidationRules{}
	err := schema.Extensions.GetObject("x-kubernetes-validations", celRules)
	if err != nil {
		allErrors = append(allErrors, fmt.Errorf("unexpected error accessing x-kubernetes-validations: %v", err.Error()))
		return nil, allErrors
	}

	var propDecls []*expr.Decl
	var root *celmodel.DeclType
	var ok bool
	env, _ := cel.NewEnv()
	reg := celmodel.NewRegistry(env)
	rt, err := celmodel.NewRuleTypes(ScopedTypeName, schema, reg)
	if err != nil {
		allErrors = append(allErrors, err)
		return nil, allErrors
	}
	opts, err := rt.EnvOptions(env.TypeProvider())
	if err != nil {
		allErrors = append(allErrors, err)
		return nil, allErrors
	}
	root, ok = rt.FindDeclType(ScopedTypeName)
	if !ok {
		root = celmodel.SchemaDeclType(schema).MaybeAssignTypeName(ScopedTypeName)
	}
	// if the type is object, will traverse each field in the object tree and declare
	if root.IsObject() {
		for k, f := range root.Fields {
			propDecls = append(propDecls, decls.NewVar(k, f.Type.ExprType()))
		}
	}
	propDecls = append(propDecls, decls.NewVar(ScopedVarName, root.ExprType()))
	opts = append(opts, cel.Declarations(propDecls...))
	env, err = env.Extend(opts...)
	if err != nil {
		allErrors = append(allErrors, err)
		return nil, allErrors
	}
	programs := make([]cel.Program, len(*celRules))
	for i, rule := range *celRules {
		if rule.Rule == "" {
			allErrors = append(allErrors, fmt.Errorf("rule is not specified"))
			return nil, allErrors
		}
		ast, issues := env.Compile(rule.Rule)
		if issues != nil {
			allErrors = append(allErrors, fmt.Errorf("compilation failed for rule: %v with message: %v", rule.Message, issues.Err()))
		} else {
			prog, err := env.Program(ast)
			if err != nil {
				allErrors = append(allErrors, fmt.Errorf("program instantiation failed for rule: %v with message: %v", rule.Message, err))
			} else {
				programs[i] = prog
			}
		}
	}

	if len(allErrors) > 0 {
		return nil, allErrors
	}
	return programs, allErrors
}
