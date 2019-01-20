// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build privileged_tests

package loader

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type LoaderTestSuite struct{}

var (
	_              = Suite(&LoaderTestSuite{})
	contextTimeout = 10 * time.Second

	dirInfo *directoryInfo
	ep      = &testEP{}
)

func Test(t *testing.T) {
	TestingT(t)
}

func (s *LoaderTestSuite) TearDownTest(c *C) {
	// Old map names as created by older versions of these tests
	//
	// FIXME GH-6701: Remove for 1.5.0
	os.Remove("/sys/fs/bpf/tc/globals/cilium_policy_foo")
	os.Remove("/sys/fs/bpf/tc/globals/cilium_calls_111")
	os.Remove("/sys/fs/bpf/tc/globals/cilium_ep_config_111")

	files, err := filepath.Glob("/sys/fs/bpf/tc/globals/test_*")
	if err != nil {
		panic(err)
	}
	for _, f := range files {
		if err := os.Remove(f); err != nil {
			panic(err)
		}
	}
}

// runTests configures devices for running the whole testsuite, and runs the
// tests. It is kept separate from TestMain() so that this function can defer
// cleanups and pass the exit code of the test run to the caller which can run
// os.Exit() with the result.
func runTests(m *testing.M) (int, error) {
	testIncludes = "-I/usr/include/x86_64-linux-gnu/"

	tmpDir, err := ioutil.TempDir("/tmp/", "cilium_")
	if err != nil {
		return 1, fmt.Errorf("Failed to create temporary directory: %s", err)
	}
	defer os.RemoveAll(tmpDir)
	if dirInfo, err = getDirs(tmpDir); err != nil {
		return 1, err
	}

	cleanup, err := prepareEnv(ep)
	if err != nil {
		return 1, fmt.Errorf("Failed to prepare environment: %s", err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			log.Errorf(err.Error())
		}
	}()

	return m.Run(), nil
}

func TestMain(m *testing.M) {
	exitCode, err := runTests(m)
	if err != nil {
		log.Fatal(err)
	}
	os.Exit(exitCode)
}

type testEP struct {
}

func (ep *testEP) InterfaceName() string {
	return "cilium_test"
}

func (ep *testEP) Logger(subsystem string) *logrus.Entry {
	return log
}

func (ep *testEP) StateDir() string {
	return "test_loader"
}

func (ep *testEP) MapPath() string {
	return "map_path"
}

func (ep *testEP) MustGraft() bool {
	return false
}

func prepareEnv(ep *testEP) (func() error, error) {
	link := netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: ep.InterfaceName(),
		},
	}
	if err := netlink.LinkAdd(&link); err != nil {
		if !os.IsExist(err) {
			return nil, fmt.Errorf("Failed to add link: %s", err)
		}
	}
	cleanupFn := func() error {
		if err := netlink.LinkDel(&link); err != nil {
			return fmt.Errorf("Failed to delete link: %s", err)
		}
		return nil
	}
	return cleanupFn, nil
}

func getDirs(tmpDir string) (*directoryInfo, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("Failed to get working directory: %s", err)
	}
	bpfdir := filepath.Join(wd, "..", "..", "..", "bpf")
	dirs := directoryInfo{
		Library: bpfdir,
		Runtime: bpfdir,
		State:   bpfdir,
		Output:  tmpDir,
	}

	return &dirs, nil
}

// TestCompileAndLoad checks that the datapath can be compiled and loaded.
func (s *LoaderTestSuite) TestCompileAndLoad(c *C) {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	err := compileAndLoad(ctx, ep, dirInfo)
	c.Assert(err, IsNil)
}

// TestReload compiles and attaches the datapath multiple times.
func (s *LoaderTestSuite) TestReload(c *C) {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	err := compileDatapath(ctx, ep, dirInfo, true)
	c.Assert(err, IsNil)

	objPath := fmt.Sprintf("%s/%s", dirInfo.Output, endpointObj)
	err = replaceDatapath(ctx, ep.InterfaceName(), objPath, symbolFromEndpoint)
	c.Assert(err, IsNil)

	err = replaceDatapath(ctx, ep.InterfaceName(), objPath, symbolFromEndpoint)
	c.Assert(err, IsNil)
}

// TestCompileFailure attempts to compile then cancels the context and ensures
// that the failure paths may be hit.
func (s *LoaderTestSuite) TestCompileFailure(c *C) {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	exit := make(chan bool)
	defer close(exit)
	go func() {
		select {
		case <-time.After(100 * time.Millisecond):
			cancel()
		case <-exit:
			break
		}
	}()

	timeout := time.Now().Add(contextTimeout)
	var err error
	for err == nil && time.Now().Before(timeout) {
		err = compileAndLoad(ctx, ep, dirInfo)
	}
	c.Assert(err, NotNil)
}

// BenchmarkCompileAndLoad benchmarks the entire compilation + loading process.
func BenchmarkCompileAndLoad(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := compileAndLoad(ctx, ep, dirInfo); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReplaceDatapath compiles the datapath program, then benchmarks only
// the loading of the program into the kernel.
func BenchmarkReplaceDatapath(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	if err := compileDatapath(ctx, ep, dirInfo, false); err != nil {
		b.Fatal(err)
	}
	objPath := fmt.Sprintf("%s/%s", dirInfo.Output, endpointObj)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := replaceDatapath(ctx, ep.InterfaceName(), objPath, symbolFromEndpoint); err != nil {
			b.Fatal(err)
		}
	}
}
