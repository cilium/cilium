// Copyright 2018-2019 Authors of Cilium
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
	"strings"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/elf"
	"github.com/cilium/cilium/pkg/maps/callsmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"

	"github.com/vishvananda/netlink"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type LoaderTestSuite struct{}

var (
	_              = Suite(&LoaderTestSuite{})
	contextTimeout = 10 * time.Second
	benchTimeout   = 5*time.Minute + 5*time.Second

	dirInfo *directoryInfo
	ep      = testutils.NewTestEndpoint()
	hostEp  = testutils.NewTestHostEndpoint()
	bpfDir  = filepath.Join(testutils.CiliumRootDir, "bpf")
)

// SetTestIncludes allows test files to configure additional include flags.
func SetTestIncludes(includes []string) {
	testIncludes = includes
}

func Test(t *testing.T) {
	TestingT(t)
}

func (s *LoaderTestSuite) SetUpSuite(c *C) {
	SetTestIncludes([]string{
		fmt.Sprintf("-I%s", bpfDir),
		fmt.Sprintf("-I%s", filepath.Join(bpfDir, "include")),
	})

	err := bpf.ConfigureResourceLimits()
	c.Assert(err, IsNil)
	sourceFile := filepath.Join(bpfDir, endpointProg)
	err = os.Symlink(sourceFile, endpointProg)
	c.Assert(err, IsNil)
	sourceFile = filepath.Join(bpfDir, hostEndpointProg)
	err = os.Symlink(sourceFile, hostEndpointProg)
	c.Assert(err, IsNil)

	// Set datapath in ipvlan mode to avoid loading the second master device.
	// Loading that second device requires a proper compilation of the
	// bpf_host.o object file with the adtual endpoint configurations, and not
	// just the template compilation as we test here.
	option.Config.DatapathMode = datapathOption.DatapathModeIpvlan
}

func (s *LoaderTestSuite) TearDownSuite(c *C) {
	SetTestIncludes(nil)
	os.RemoveAll(endpointProg)
	os.RemoveAll(hostEndpointProg)
}

func (s *LoaderTestSuite) TearDownTest(c *C) {
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
	SetTestIncludes([]string{"-I/usr/include/x86_64-linux-gnu/"})
	defer SetTestIncludes(nil)

	tmpDir, err := ioutil.TempDir("/tmp/", "cilium_")
	if err != nil {
		return 1, fmt.Errorf("Failed to create temporary directory: %s", err)
	}
	defer os.RemoveAll(tmpDir)
	dirInfo = getDirs(tmpDir)

	cleanup, err := prepareEnv(&ep)
	if err != nil {
		return 1, fmt.Errorf("Failed to prepare environment: %s", err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			log.Error(err.Error())
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

func prepareEnv(ep *testutils.TestEndpoint) (func() error, error) {
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

func getDirs(tmpDir string) *directoryInfo {
	return &directoryInfo{
		Library: bpfDir,
		Runtime: bpfDir,
		State:   bpfDir,
		Output:  tmpDir,
	}
}

func (s *LoaderTestSuite) testCompileAndLoad(c *C, ep *testutils.TestEndpoint) {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()
	stats := &metrics.SpanStat{}

	l := &Loader{}
	err := l.compileAndLoad(ctx, ep, dirInfo, stats)
	c.Assert(err, IsNil)
}

// TestCompileAndLoadDefaultEndpoint checks that the datapath can be compiled
// and loaded.
func (s *LoaderTestSuite) TestCompileAndLoadDefaultEndpoint(c *C) {
	s.testCompileAndLoad(c, &ep)
}

// TestCompileAndLoadHostEndpoint is the same as
// TestCompileAndLoadDefaultEndpoint, but for the host endpoint.
func (s *LoaderTestSuite) TestCompileAndLoadHostEndpoint(c *C) {
	s.testCompileAndLoad(c, &hostEp)
}

// TestReload compiles and attaches the datapath multiple times.
func (s *LoaderTestSuite) TestReload(c *C) {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	err := compileDatapath(ctx, dirInfo, false, log)
	c.Assert(err, IsNil)

	objPath := fmt.Sprintf("%s/%s", dirInfo.Output, endpointObj)
	l := &Loader{}
	err = l.replaceDatapath(ctx, ep.InterfaceName(), objPath, symbolFromEndpoint, dirIngress)
	c.Assert(err, IsNil)

	err = l.replaceDatapath(ctx, ep.InterfaceName(), objPath, symbolFromEndpoint, dirIngress)
	c.Assert(err, IsNil)
}

func (s *LoaderTestSuite) testCompileFailure(c *C, ep *testutils.TestEndpoint) {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	exit := make(chan struct{})
	defer close(exit)
	go func() {
		select {
		case <-time.After(100 * time.Millisecond):
			cancel()
		case <-exit:
			break
		}
	}()

	l := &Loader{}
	timeout := time.Now().Add(contextTimeout)
	var err error
	stats := &metrics.SpanStat{}
	for err == nil && time.Now().Before(timeout) {
		err = l.compileAndLoad(ctx, ep, dirInfo, stats)
	}
	c.Assert(err, NotNil)
}

// TestCompileFailureDefaultEndpoint attempts to compile then cancels the
// context and ensures that the failure paths may be hit.
func (s *LoaderTestSuite) TestCompileFailureDefaultEndpoint(c *C) {
	s.testCompileFailure(c, &ep)
}

// TestCompileFailureHostEndpoint is the same as
// TestCompileFailureDefaultEndpoint, but for the host endpoint.
func (s *LoaderTestSuite) TestCompileFailureHostEndpoint(c *C) {
	s.testCompileFailure(c, &hostEp)
}

// BenchmarkCompileOnly benchmarks the just the entire compilation process.
func BenchmarkCompileOnly(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), benchTimeout)
	defer cancel()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := compileDatapath(ctx, dirInfo, false, log); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCompileAndLoad benchmarks the entire compilation + loading process.
func BenchmarkCompileAndLoad(b *testing.B) {
	stats := &metrics.SpanStat{}
	ctx, cancel := context.WithTimeout(context.Background(), benchTimeout)
	defer cancel()

	l := &Loader{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := l.compileAndLoad(ctx, &ep, dirInfo, stats); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReplaceDatapath compiles the datapath program, then benchmarks only
// the loading of the program into the kernel.
func BenchmarkReplaceDatapath(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), benchTimeout)
	defer cancel()

	if err := compileDatapath(ctx, dirInfo, false, log); err != nil {
		b.Fatal(err)
	}

	l := &Loader{}
	objPath := fmt.Sprintf("%s/%s", dirInfo.Output, endpointObj)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := l.replaceDatapath(ctx, ep.InterfaceName(), objPath, symbolFromEndpoint, dirIngress); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCompileOrLoad benchmarks the ELF rewrite process.
func BenchmarkCompileOrLoad(b *testing.B) {
	ignorePrefixes := append(ignoredELFPrefixes, "test_cilium_policy")
	for _, p := range ignoredELFPrefixes {
		if strings.HasPrefix(p, "cilium_") {
			testPrefix := fmt.Sprintf("test_%s", p)
			ignorePrefixes = append(ignorePrefixes, testPrefix)
		}
	}
	elf.IgnoreSymbolPrefixes(ignorePrefixes)

	SetTestIncludes([]string{
		fmt.Sprintf("-I%s", bpfDir),
		fmt.Sprintf("-I%s", filepath.Join(bpfDir, "include")),
	})
	defer SetTestIncludes(nil)

	elfMapPrefixes = []string{
		fmt.Sprintf("test_%s", policymap.MapName),
		fmt.Sprintf("test_%s", callsmap.MapName),
	}

	sourceFile := filepath.Join(bpfDir, endpointProg)
	if err := os.Symlink(sourceFile, endpointProg); err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(endpointProg)

	ctx, cancel := context.WithTimeout(context.Background(), benchTimeout)
	defer cancel()

	tmpDir, err := ioutil.TempDir("", "cilium_test")
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	epDir := ep.StateDir()
	if err := os.MkdirAll(epDir, 0755); err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(epDir)

	l := &Loader{}
	l.templateCache = newObjectCache(&config.HeaderfileWriter{}, nil, tmpDir)
	if err := l.CompileOrLoad(ctx, &ep, nil); err != nil {
		log.Warningf("Failure in %s: %s", tmpDir, err)
		time.Sleep(1 * time.Minute)
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := l.CompileOrLoad(ctx, &ep, nil); err != nil {
			b.Fatal(err)
		}
	}
}
