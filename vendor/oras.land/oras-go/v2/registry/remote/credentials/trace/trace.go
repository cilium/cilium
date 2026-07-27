/*
Copyright The ORAS Authors.
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

package trace

import "context"

// executableTraceContextKey is a value key used to retrieve the ExecutableTrace
// from Context.
type executableTraceContextKey struct{}

// ExecutableTrace is a set of hooks used to trace the execution of binary
// executables. Any particular hook may be nil.
type ExecutableTrace struct {
	// ExecuteStart is called before the execution of the executable. The
	// executableName parameter is the name of the credential helper executable
	// used with NativeStore. The action parameter is one of "store", "get" and
	// "erase".
	//
	// Reference:
	//   - https://docs.docker.com/engine/reference/commandline/login#credentials-store
	ExecuteStart func(executableName string, action string)

	// ExecuteDone is called after the execution of an executable completes.
	// The executableName parameter is the name of the credential helper
	// executable used with NativeStore. The action parameter is one of "store",
	// "get" and "erase". The err parameter is the error (if any) returned from
	// the execution.
	//
	// Reference:
	//   - https://docs.docker.com/engine/reference/commandline/login#credentials-store
	ExecuteDone func(executableName string, action string, err error)
}

// ContextExecutableTrace returns the ExecutableTrace associated with the
// context. If none, it returns nil.
func ContextExecutableTrace(ctx context.Context) *ExecutableTrace {
	trace, _ := ctx.Value(executableTraceContextKey{}).(*ExecutableTrace)
	return trace
}

// WithExecutableTrace takes a Context and an ExecutableTrace, and returns a
// Context with the ExecutableTrace added as a Value. If the Context has a
// previously added trace, the hooks defined in the new trace will be added
// in addition to the previous ones. The recent hooks will be called first.
func WithExecutableTrace(ctx context.Context, trace *ExecutableTrace) context.Context {
	if trace == nil {
		return ctx
	}
	if oldTrace := ContextExecutableTrace(ctx); oldTrace != nil {
		trace.compose(oldTrace)
	}
	return context.WithValue(ctx, executableTraceContextKey{}, trace)
}

// compose takes an oldTrace and modifies the existing trace to include
// the hooks defined in the oldTrace. The hooks in the existing trace will
// be called first.
func (trace *ExecutableTrace) compose(oldTrace *ExecutableTrace) {
	if oldStart := oldTrace.ExecuteStart; oldStart != nil {
		start := trace.ExecuteStart
		if start != nil {
			trace.ExecuteStart = func(executableName, action string) {
				start(executableName, action)
				oldStart(executableName, action)
			}
		} else {
			trace.ExecuteStart = oldStart
		}
	}
	if oldDone := oldTrace.ExecuteDone; oldDone != nil {
		done := trace.ExecuteDone
		if done != nil {
			trace.ExecuteDone = func(executableName, action string, err error) {
				done(executableName, action, err)
				oldDone(executableName, action, err)
			}
		} else {
			trace.ExecuteDone = oldDone
		}
	}
}
