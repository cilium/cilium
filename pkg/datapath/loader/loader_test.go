// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/cilium/checkmate"
	"github.com/vishvananda/netlink"

	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/cilium/pkg/datapath/linux/config"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/elf"
	"github.com/cilium/cilium/pkg/maps/callsmap"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

// Hook up gocheck into the "go test" runner.
type LoaderTestSuite struct {
	teardown func() error
}

var (
	_              = Suite(&LoaderTestSuite{})
	contextTimeout = 10 * time.Second
	benchTimeout   = 5*time.Minute + 5*time.Second

	dirInfo *directoryInfo
	ep      = testutils.NewTestEndpoint()
	hostEp  = testutils.NewTestHostEndpoint()
	bpfDir  = filepath.Join("..", "..", "..", "bpf")
)

// SetTestIncludes allows test files to configure additional include flags.
func SetTestIncludes(includes []string) {
	testIncludes = includes
}

func Test(t *testing.T) {
	TestingT(t)
}

func (s *LoaderTestSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)

	tmpDir, err := os.MkdirTemp("/tmp/", "cilium_")
	if err != nil {
		c.Fatalf("Failed to create temporary directory: %s", err)
	}
	dirInfo = getDirs(tmpDir)

	cleanup, err := prepareEnv(&ep)
	if err != nil {
		SetTestIncludes(nil)
		os.RemoveAll(tmpDir)
		c.Fatalf("Failed to prepare environment: %s", err)
	}

	s.teardown = func() error {
		if err := cleanup(); err != nil {
			return err
		}
		return os.RemoveAll(tmpDir)
	}

	ctmap.InitMapInfo(option.CTMapEntriesGlobalTCPDefault, option.CTMapEntriesGlobalAnyDefault, true, true, true)

	SetTestIncludes([]string{
		fmt.Sprintf("-I%s", bpfDir),
		fmt.Sprintf("-I%s", filepath.Join(bpfDir, "include")),
	})

	c.Assert(rlimit.RemoveMemlock(), IsNil)

	sourceFile := filepath.Join(bpfDir, endpointProg)
	c.Assert(os.Symlink(sourceFile, endpointProg), IsNil)

	sourceFile = filepath.Join(bpfDir, hostEndpointProg)
	c.Assert(os.Symlink(sourceFile, hostEndpointProg), IsNil)
}

func (s *LoaderTestSuite) TearDownSuite(c *C) {
	SetTestIncludes(nil)
	os.RemoveAll(endpointProg)
	os.RemoveAll(hostEndpointProg)

	if s.teardown != nil {
		if err := s.teardown(); err != nil {
			c.Fatal(err)
		}
	}
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
	elfMapPrefixes = []string{
		fmt.Sprintf("test_%s", policymap.MapName),
		fmt.Sprintf("test_%s", callsmap.MapName),
	}

	callsmap.HostMapName = fmt.Sprintf("test_%s", callsmap.MapName)
	callsmap.NetdevMapName = fmt.Sprintf("test_%s", callsmap.MapName)

	epDir := ep.StateDir()
	err := os.MkdirAll(epDir, 0755)
	c.Assert(err, IsNil)
	defer os.RemoveAll(epDir)

	s.testCompileAndLoad(c, &hostEp)
}

// TestReload compiles and attaches the datapath multiple times.
func (s *LoaderTestSuite) TestReload(c *C) {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	err := compileDatapath(ctx, dirInfo, false, log)
	c.Assert(err, IsNil)

	objPath := fmt.Sprintf("%s/%s", dirInfo.Output, endpointObj)
	progs := []progDefinition{
		{progName: symbolFromEndpoint, direction: dirIngress},
		{progName: symbolToEndpoint, direction: dirEgress},
	}
	finalize, err := replaceDatapath(ctx, ep.InterfaceName(), objPath, progs, "")
	c.Assert(err, IsNil)
	finalize()

	finalize, err = replaceDatapath(ctx, ep.InterfaceName(), objPath, progs, "")
	c.Assert(err, IsNil)
	finalize()
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

	objPath := fmt.Sprintf("%s/%s", dirInfo.Output, endpointObj)
	progs := []progDefinition{{progName: symbolFromEndpoint, direction: dirIngress}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		finalize, err := replaceDatapath(ctx, ep.InterfaceName(), objPath, progs, "")
		if err != nil {
			b.Fatal(err)
		}
		finalize()
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

	tmpDir, err := os.MkdirTemp("", "cilium_test")
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
