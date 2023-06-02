package check

import (
	"errors"
	"flag"
	"fmt"
	"testing"
	"time"
)

// -----------------------------------------------------------------------
// Test suite registry.

var allSuites []interface{}

// Suite registers the given value as a test suite to be run. Any methods
// starting with the Test prefix in the given value will be considered as
// a test method.
func Suite(suite interface{}) interface{} {
	allSuites = append(allSuites, suite)
	return suite
}

// -----------------------------------------------------------------------
// Public running interface.

func init() {
	for _, f := range []struct {
		flag        string
		replacement string
	}{
		{"gocheck.f", "-run"},
		{"gocheck.v", "-v"},
		{"gocheck.vv", "-v -count 1"},
		{"gocheck.list", ""},
		{"gocheck.work", ""},
		{"check.f", "-run"},
		{"check.v", "-v"},
		{"check.vv", "-v -count 1"},
		{"check.list", ""},
		{"check.work", ""},
	} {
		flag.Var(&deprecatedFlag{f.replacement}, f.flag, "deprecated")
	}
}

var (
	oldBenchFlag = flag.Bool("gocheck.b", false, "Run benchmarks")
	oldBenchTime = flag.Duration("gocheck.btime", 1*time.Second, "approximate run time for each benchmark")
	newBenchFlag = flag.Bool("check.b", false, "Run benchmarks")
	newBenchTime = flag.Duration("check.btime", 1*time.Second, "approximate run time for each benchmark")
	newBenchMem  = flag.Bool("check.bmem", false, "Report memory benchmarks")
)

type deprecatedFlag struct {
	replacement string
}

var _ flag.Value = (*deprecatedFlag)(nil)

func (df *deprecatedFlag) String() string {
	return ""
}

func (df *deprecatedFlag) Set(string) error {
	if df.replacement == "" {
		return errors.New("deprecated flag")
	}

	return fmt.Errorf("deprecated: use %s instead", df.replacement)
}

// TestingT runs all test suites registered with the Suite function,
// printing results to stdout, and reporting any failures back to
// the "testing" package.
func TestingT(testingT *testing.T) {
	benchTime := *newBenchTime
	if benchTime == 1*time.Second {
		benchTime = *oldBenchTime
	}
	conf := &RunConf{
		Benchmark:     *oldBenchFlag || *newBenchFlag,
		BenchmarkTime: benchTime,
		BenchmarkMem:  *newBenchMem,
	}
	RunAll(testingT, conf)
}

// RunAll runs all test suites registered with the Suite function, using the
// provided run configuration.
func RunAll(t *testing.T, runConf *RunConf) {
	for _, suite := range allSuites {
		Run(t, suite, runConf)
	}
}

// Run runs the provided test suite using the provided run configuration.
func Run(t *testing.T, suite interface{}, runConf *RunConf) {
	runner := newSuiteRunner(suite, runConf)
	runner.run(t)
}

// ListAll returns the names of all the test functions registered with the
// Suite function that will be run with the provided run configuration.
func ListAll(runConf *RunConf) []string {
	var names []string
	for _, suite := range allSuites {
		names = append(names, List(suite, runConf)...)
	}
	return names
}

// List returns the names of the test functions in the given
// suite that will be run with the provided run configuration.
func List(suite interface{}, runConf *RunConf) []string {
	var names []string
	runner := newSuiteRunner(suite, runConf)
	for _, t := range runner.tests {
		names = append(names, t.String())
	}
	return names
}

// -----------------------------------------------------------------------
// Result methods.

func (r *Result) Add(other *Result) {
	r.Succeeded += other.Succeeded
	r.Skipped += other.Skipped
	r.Failed += other.Failed
	r.Panicked += other.Panicked
	r.FixturePanicked += other.FixturePanicked
	r.ExpectedFailures += other.ExpectedFailures
	r.Missed += other.Missed
	if r.WorkDir != "" && other.WorkDir != "" {
		r.WorkDir += ":" + other.WorkDir
	} else if other.WorkDir != "" {
		r.WorkDir = other.WorkDir
	}
}

func (r *Result) Passed() bool {
	return (r.Failed == 0 && r.Panicked == 0 &&
		r.FixturePanicked == 0 && r.Missed == 0 &&
		r.RunError == nil)
}

func (r *Result) String() string {
	if r.RunError != nil {
		return "ERROR: " + r.RunError.Error()
	}

	var value string
	if r.Failed == 0 && r.Panicked == 0 && r.FixturePanicked == 0 &&
		r.Missed == 0 {
		value = "OK: "
	} else {
		value = "OOPS: "
	}
	value += fmt.Sprintf("%d passed", r.Succeeded)
	if r.Skipped != 0 {
		value += fmt.Sprintf(", %d skipped", r.Skipped)
	}
	if r.ExpectedFailures != 0 {
		value += fmt.Sprintf(", %d expected failures", r.ExpectedFailures)
	}
	if r.Failed != 0 {
		value += fmt.Sprintf(", %d FAILED", r.Failed)
	}
	if r.Panicked != 0 {
		value += fmt.Sprintf(", %d PANICKED", r.Panicked)
	}
	if r.FixturePanicked != 0 {
		value += fmt.Sprintf(", %d FIXTURE-PANICKED", r.FixturePanicked)
	}
	if r.Missed != 0 {
		value += fmt.Sprintf(", %d MISSED", r.Missed)
	}
	if r.WorkDir != "" {
		value += "\nWORK=" + r.WorkDir
	}
	return value
}
