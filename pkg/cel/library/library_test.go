// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package library_test

import (
	"regexp"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/stretchr/testify/require"
)

var (
	trueVal  = types.Bool(true)
	falseVal = types.Bool(false)
)

// testCEL is a generic helper that compiles and evaluates a CEL expression.
// envOpts configures the environment; arg is bound to varName in the activation.
func testCEL(
	t *testing.T,
	envOpts []cel.EnvOption,
	varName string,
	expr string,
	arg any,
	expectResult ref.Val,
	expectRuntimeErr string,
	expectCompileErrs []string,
) {
	t.Helper()

	env, err := cel.NewEnv(envOpts...)
	require.NoError(t, err)

	compiled, issues := env.Compile(expr)

	if len(expectCompileErrs) > 0 {
		for _, expectErr := range expectCompileErrs {
			pattern, err := regexp.Compile(expectErr)
			require.NoErrorf(t, err, "failed to compile error pattern %q", expectErr)
			found := false
			errMsgs := []string{}
			for _, compileErr := range issues.Errors() {
				errMsgs = append(errMsgs, compileErr.Message)
				if pattern.MatchString(compileErr.Message) {
					found = true
					break
				}
			}
			require.Truef(t, found, "expected compile error matching %q, got: %v", expectErr, errMsgs)
		}
		return
	}
	require.NoError(t, issues.Err(), "unexpected compile error")

	prog, err := env.Program(compiled)
	require.NoError(t, err)

	res, _, err := prog.Eval(map[string]any{varName: arg})
	if expectRuntimeErr != "" {
		require.Error(t, err)
		require.Regexp(t, expectRuntimeErr, err.Error())
		return
	}
	require.NoError(t, err)
	require.NotNil(t, expectResult, "expectResult must not be nil when no error is expected")
	converted := res.Equal(expectResult)
	require.Truef(t, converted != types.False && converted != types.OptionalNone,
		"expected %v (%T), got %v (%T)", expectResult, expectResult, res, res)
}
