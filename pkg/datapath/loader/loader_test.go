// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"fmt"
	"net/netip"
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
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/elf"
	"github.com/cilium/cilium/pkg/maps/callsmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb"
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

	ep     = testutils.NewTestEndpoint()
	hostEp = testutils.NewTestHostEndpoint()
	bpfDir = filepath.Join("..", "..", "..", "bpf")
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

	node.SetTestLocalNodeStore()

	cleanup, err := prepareEnv(&ep)
	if err != nil {
		SetTestIncludes(nil)
		c.Fatalf("Failed to prepare environment: %s", err)
	}

	s.teardown = cleanup

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
	node.UnsetTestLocalNodeStore()
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

func getDirs(tb testing.TB) *directoryInfo {
	return &directoryInfo{
		Library: bpfDir,
		Runtime: bpfDir,
		State:   bpfDir,
		Output:  tb.TempDir(),
	}
}

func (s *LoaderTestSuite) testCompileAndLoad(c *C, ep *testutils.TestEndpoint) {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()
	stats := &metrics.SpanStat{}

	l := NewLoaderForTest(c)
	err := l.compileAndLoad(ctx, ep, getDirs(c), stats)
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

	dirInfo := getDirs(c)
	err := compileDatapath(ctx, dirInfo, false, log)
	c.Assert(err, IsNil)

	objPath := fmt.Sprintf("%s/%s", dirInfo.Output, endpointObj)
	progs := []progDefinition{
		{progName: symbolFromEndpoint, direction: dirIngress},
		{progName: symbolToEndpoint, direction: dirEgress},
	}
	opts := replaceDatapathOptions{
		device:   ep.InterfaceName(),
		elf:      objPath,
		programs: progs,
		linkDir:  testutils.TempBPFFS(c),
	}
	finalize, err := replaceDatapath(ctx, opts)
	c.Assert(err, IsNil)
	finalize()

	finalize, err = replaceDatapath(ctx, opts)

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

	l := NewLoaderForTest(c)
	timeout := time.Now().Add(contextTimeout)
	var err error
	stats := &metrics.SpanStat{}
	for err == nil && time.Now().Before(timeout) {
		err = l.compileAndLoad(ctx, ep, getDirs(c), stats)
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

func (s *LoaderTestSuite) TestBPFMasqAddrs(c *C) {
	old4 := option.Config.EnableIPv4Masquerade
	option.Config.EnableIPv4Masquerade = true
	old6 := option.Config.EnableIPv4Masquerade
	option.Config.EnableIPv6Masquerade = true
	c.Cleanup(func() {
		option.Config.EnableIPv4Masquerade = old4
		option.Config.EnableIPv6Masquerade = old6
	})

	l := NewLoaderForTest(c)
	nodeAddrs := l.nodeAddrs.(statedb.RWTable[tables.NodeAddress])
	db := l.db

	masq4, masq6 := l.bpfMasqAddrs("test")
	c.Assert(masq4.IsValid(), Equals, false)
	c.Assert(masq6.IsValid(), Equals, false)

	txn := db.WriteTxn(nodeAddrs)
	nodeAddrs.Insert(txn, tables.NodeAddress{
		Addr:       netip.MustParseAddr("1.0.0.1"),
		NodePort:   true,
		Primary:    true,
		DeviceName: "test",
	})
	nodeAddrs.Insert(txn, tables.NodeAddress{
		Addr:       netip.MustParseAddr("1000::1"),
		NodePort:   true,
		Primary:    true,
		DeviceName: "test",
	})
	nodeAddrs.Insert(txn, tables.NodeAddress{
		Addr:       netip.MustParseAddr("2.0.0.2"),
		NodePort:   false,
		Primary:    true,
		DeviceName: tables.WildcardDeviceName,
	})
	nodeAddrs.Insert(txn, tables.NodeAddress{
		Addr:       netip.MustParseAddr("2000::2"),
		NodePort:   false,
		Primary:    true,
		DeviceName: tables.WildcardDeviceName,
	})
	txn.Commit()

	masq4, masq6 = l.bpfMasqAddrs("test")
	c.Assert(masq4.String(), Equals, "1.0.0.1")
	c.Assert(masq6.String(), Equals, "1000::1")

	masq4, masq6 = l.bpfMasqAddrs("unknown")
	c.Assert(masq4.String(), Equals, "2.0.0.2")
	c.Assert(masq6.String(), Equals, "2000::2")
}

// BenchmarkCompileOnly benchmarks the just the entire compilation process.
func BenchmarkCompileOnly(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), benchTimeout)
	defer cancel()

	dirInfo := getDirs(b)
	option.Config.Debug = true

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

	l := NewLoaderForTest(b)
	dirInfo := getDirs(b)

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

	dirInfo := getDirs(b)

	if err := compileDatapath(ctx, dirInfo, false, log); err != nil {
		b.Fatal(err)
	}

	objPath := fmt.Sprintf("%s/%s", dirInfo.Output, endpointObj)
	linkDir := testutils.TempBPFFS(b)
	progs := []progDefinition{{progName: symbolFromEndpoint, direction: dirIngress}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		finalize, err := replaceDatapath(ctx,
			replaceDatapathOptions{
				device:   ep.InterfaceName(),
				elf:      objPath,
				programs: progs,
				linkDir:  linkDir,
			},
		)
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

	l := NewLoaderForTest(b)
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
