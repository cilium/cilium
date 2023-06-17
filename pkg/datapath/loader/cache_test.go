// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"fmt"
	"os"
	"time"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/datapath/linux/config"
	"github.com/cilium/cilium/pkg/testutils"
)

func (s *LoaderTestSuite) TestobjectCache(c *C) {
	tmpDir, err := os.MkdirTemp("", "cilium_test")
	c.Assert(err, IsNil)
	defer os.RemoveAll(tmpDir)

	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	cache := newObjectCache(&config.HeaderfileWriter{}, nil, tmpDir)
	realEP := testutils.NewTestEndpoint()

	// First run should compile and generate the object.
	_, isNew, err := cache.fetchOrCompile(ctx, &realEP, nil)
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, true)

	// Same EP should not be compiled twice.
	_, isNew, err = cache.fetchOrCompile(ctx, &realEP, nil)
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, false)

	// Changing the ID should not generate a new object.
	realEP.Id++
	_, isNew, err = cache.fetchOrCompile(ctx, &realEP, nil)
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, false)

	// Changing a setting on the EP should generate a new object.
	realEP.Opts.SetBool("foo", true)
	_, isNew, err = cache.fetchOrCompile(ctx, &realEP, nil)
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, true)
}

type buildResult struct {
	goroutine int
	path      string
	compiled  bool
	err       error
}

func receiveResult(c *C, results chan buildResult) (*buildResult, error) {
	select {
	case result := <-results:
		if result.err != nil {
			return nil, result.err
		}
		return &result, nil
	case <-time.After(contextTimeout):
		return nil, fmt.Errorf("Timed out waiting for goroutines to return")
	}
}

func (s *LoaderTestSuite) TestobjectCacheParallel(c *C) {
	tmpDir, err := os.MkdirTemp("", "cilium_test")
	c.Assert(err, IsNil)
	defer os.RemoveAll(tmpDir)

	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	tests := []struct {
		description string
		builds      int
		divisor     int
	}{
		{
			description: "One build, multiple blocking goroutines",
			builds:      8,
			divisor:     8,
		},
		{
			description: "Eight builds, half compile, half block",
			builds:      8,
			divisor:     2,
		},
		{
			description: "Eight unique builds",
			builds:      8,
			divisor:     1,
		},
	}

	for _, t := range tests {
		c.Logf("  %s", t.description)

		results := make(chan buildResult, t.builds)
		cache := newObjectCache(&config.HeaderfileWriter{}, nil, tmpDir)
		for i := 0; i < t.builds; i++ {
			go func(i int) {
				ep := testutils.NewTestEndpoint()
				opt := fmt.Sprintf("OPT%d", i/t.divisor)
				ep.Opts.SetBool(opt, true)
				path, isNew, err := cache.fetchOrCompile(ctx, &ep, nil)
				results <- buildResult{
					goroutine: i,
					path:      path,
					compiled:  isNew,
					err:       err,
				}
			}(i)
		}

		// First result will always be a compilation for the new set of options
		compiled := make(map[string]int, t.builds)
		used := make(map[string]int, t.builds)
		for i := 0; i < t.builds; i++ {
			result, err := receiveResult(c, results)
			c.Assert(err, IsNil)

			used[result.path] = used[result.path] + 1
			if result.compiled {
				compiled[result.path] = compiled[result.path] + 1
			}
		}

		c.Assert(len(compiled), Equals, t.builds/t.divisor)
		c.Assert(len(used), Equals, t.builds/t.divisor)
		for _, templateCompileCount := range compiled {
			// Only one goroutine compiles each template
			c.Assert(templateCompileCount, Equals, 1)
		}
		for _, templateUseCount := range used {
			// Based on the test parameters, a number of goroutines
			// may share the same template.
			c.Assert(templateUseCount, Equals, t.divisor)
		}
	}
}
