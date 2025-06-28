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

package syncutil

import (
	"context"

	"golang.org/x/sync/errgroup"
)

// LimitedGroup is a collection of goroutines working on subtasks that are part of
// the same overall task.
type LimitedGroup struct {
	grp *errgroup.Group
	ctx context.Context
}

// LimitGroup returns a new LimitedGroup and an associated Context derived from ctx.
//
// The number of active goroutines in this group is limited to the given limit.
// A negative value indicates no limit.
//
// The derived Context is canceled the first time a function passed to Go
// returns a non-nil error or the first time Wait returns, whichever occurs
// first.
func LimitGroup(ctx context.Context, limit int) (*LimitedGroup, context.Context) {
	grp, ctx := errgroup.WithContext(ctx)
	grp.SetLimit(limit)
	return &LimitedGroup{grp: grp, ctx: ctx}, ctx
}

// Go calls the given function in a new goroutine.
// It blocks until the new goroutine can be added without the number of
// active goroutines in the group exceeding the configured limit.
//
// The first call to return a non-nil error cancels the group's context.
// After which, any subsequent calls to Go will not execute their given function.
// The error will be returned by Wait.
func (g *LimitedGroup) Go(f func() error) {
	g.grp.Go(func() error {
		select {
		case <-g.ctx.Done():
			return g.ctx.Err()
		default:
			return f()
		}
	})
}

// Wait blocks until all function calls from the Go method have returned, then
// returns the first non-nil error (if any) from them.
func (g *LimitedGroup) Wait() error {
	return g.grp.Wait()
}
