// Package check helps you migrate off of gopkg.in/check.v1
package check

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// -----------------------------------------------------------------------
// Internal type which deals with suite method calling.

const (
	fixtureKd = iota
	testKd
)

type funcKind int

const (
	succeededSt = iota
	failedSt
	skippedSt
	panickedSt
	fixturePanickedSt
	missedSt
)

type funcStatus uint32

// A method value can't reach its own Method structure.
type methodType struct {
	reflect.Value
	Info reflect.Method
}

func newMethod(receiver reflect.Value, i int) *methodType {
	return &methodType{receiver.Method(i), receiver.Type().Method(i)}
}

func (method *methodType) PC() uintptr {
	return method.Info.Func.Pointer()
}

func (method *methodType) suiteName() string {
	t := method.Info.Type.In(0)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t.Name()
}

func (method *methodType) String() string {
	return method.Info.Name
}

func (method *methodType) matches(re *regexp.Regexp) bool {
	return (re.MatchString(method.Info.Name) ||
		re.MatchString(method.suiteName()) ||
		re.MatchString(method.String()))
}

type C struct {
	*testing.T
	method    *methodType
	kind      funcKind
	testName  string
	logb      *logger
	logw      io.Writer
	done      chan *C
	reason    string
	mustFail  bool
	benchMem  bool
	startTime time.Time
	timer
}

var _ testing.TB = (*C)(nil)

// logger is a concurrency safe byte.Buffer
type logger struct {
	sync.Mutex
	writer bytes.Buffer
}

func (l *logger) Write(buf []byte) (int, error) {
	l.Lock()
	defer l.Unlock()
	return l.writer.Write(buf)
}

func (l *logger) WriteTo(w io.Writer) (int64, error) {
	l.Lock()
	defer l.Unlock()
	return l.writer.WriteTo(w)
}

func (l *logger) String() string {
	l.Lock()
	defer l.Unlock()
	return l.writer.String()
}

// Create a new temporary directory which is automatically removed after
// the suite finishes running.
func (c *C) MkDir() string {
	return c.T.TempDir()
}

// -----------------------------------------------------------------------
// Low-level logging functions.

func (c *C) log(args ...interface{}) {
	c.writeLog([]byte(fmt.Sprint(args...) + "\n"))
}

func (c *C) logf(format string, args ...interface{}) {
	c.writeLog([]byte(fmt.Sprintf(format+"\n", args...)))
}

func (c *C) logNewLine() {
	c.writeLog([]byte{'\n'})
}

func (c *C) writeLog(buf []byte) {
	c.logb.Write(buf)
	if c.logw != nil {
		c.logw.Write(buf)
	}
}

func hasStringOrError(x interface{}) (ok bool) {
	_, ok = x.(fmt.Stringer)
	if ok {
		return
	}
	_, ok = x.(error)
	return
}

func (c *C) logValue(label string, value interface{}) {
	if label == "" {
		if hasStringOrError(value) {
			c.logf("... %#v (%q)", value, value)
		} else {
			c.logf("... %#v", value)
		}
	} else if value == nil {
		c.logf("... %s = nil", label)
	} else {
		if hasStringOrError(value) {
			fv := fmt.Sprintf("%#v", value)
			qv := fmt.Sprintf("%q", value)
			if fv != qv {
				c.logf("... %s %s = %s (%s)", label, reflect.TypeOf(value), fv, qv)
				return
			}
		}
		if s, ok := value.(string); ok && isMultiLine(s) {
			c.logf(`... %s %s = "" +`, label, reflect.TypeOf(value))
			c.logMultiLine(s)
		} else {
			c.logf("... %s %s = %#v", label, reflect.TypeOf(value), value)
		}
	}
}

func formatMultiLine(s string, quote bool) []byte {
	b := make([]byte, 0, len(s)*2)
	i := 0
	n := len(s)
	for i < n {
		j := i + 1
		for j < n && s[j-1] != '\n' {
			j++
		}
		b = append(b, "...     "...)
		if quote {
			b = strconv.AppendQuote(b, s[i:j])
		} else {
			b = append(b, s[i:j]...)
			b = bytes.TrimSpace(b)
		}
		if quote && j < n {
			b = append(b, " +"...)
		}
		b = append(b, '\n')
		i = j
	}
	return b
}

func (c *C) logMultiLine(s string) {
	c.writeLog(formatMultiLine(s, true))
}

func isMultiLine(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '\n' {
			return true
		}
	}
	return false
}

func (c *C) logString(issue string) {
	c.log("... ", issue)
}

func (c *C) logCaller(skip int) {
	// This is a bit heavier than it ought to be.
	skip++ // Our own frame.
	pc, callerFile, callerLine, ok := runtime.Caller(skip)
	if !ok {
		return
	}
	var testFile string
	var testLine int
	testFunc := runtime.FuncForPC(c.method.PC())
	if runtime.FuncForPC(pc) != testFunc {
		for {
			skip++
			if pc, file, line, ok := runtime.Caller(skip); ok {
				// Note that the test line may be different on
				// distinct calls for the same test.  Showing
				// the "internal" line is helpful when debugging.
				if runtime.FuncForPC(pc) == testFunc {
					testFile, testLine = file, line
					break
				}
			} else {
				break
			}
		}
	}
	if testFile != "" && (testFile != callerFile || testLine != callerLine) {
		c.logCode(testFile, testLine)
	}
	c.logCode(callerFile, callerLine)
}

func (c *C) logCode(path string, line int) {
	c.logf("%s:%d:", nicePath(path), line)
	code, err := printLine(path, line)
	if code == "" {
		code = "..." // XXX Open the file and take the raw line.
		if err != nil {
			code += err.Error()
		}
	}
	c.log(indent(code, "    "))
}

var valueGo = filepath.Join("reflect", "value.go")
var asmGo = filepath.Join("runtime", "asm_")

func (c *C) logPanic(skip int, value interface{}) {
	skip++ // Our own frame.
	initialSkip := skip
	for ; ; skip++ {
		if pc, file, line, ok := runtime.Caller(skip); ok {
			if skip == initialSkip {
				c.logf("... Panic: %s (PC=0x%X)\n", value, pc)
			}
			name := niceFuncName(pc)
			path := nicePath(file)
			if strings.Contains(path, "/gopkg.in/check.v") {
				continue
			}
			if name == "Value.call" && strings.HasSuffix(path, valueGo) {
				continue
			}
			if (name == "call16" || name == "call32") && strings.Contains(path, asmGo) {
				continue
			}
			c.logf("%s:%d\n  in %s", nicePath(file), line, name)
		} else {
			break
		}
	}
}

func (c *C) logSoftPanic(issue string) {
	c.log("... Panic: ", issue)
}

func (c *C) logArgPanic(method *methodType, expectedType string) {
	c.Fatalf("... Panic: %s argument should be %s",
		niceFuncName(method.PC()), expectedType)
}

// -----------------------------------------------------------------------
// Some simple formatting helpers.

var initWD, initWDErr = os.Getwd()

func init() {
	if initWDErr == nil {
		initWD = strings.Replace(initWD, "\\", "/", -1) + "/"
	}
}

func nicePath(path string) string {
	if initWDErr == nil {
		if strings.HasPrefix(path, initWD) {
			return path[len(initWD):]
		}
	}
	return path
}

func niceFuncPath(pc uintptr) string {
	function := runtime.FuncForPC(pc)
	if function != nil {
		filename, line := function.FileLine(pc)
		return fmt.Sprintf("%s:%d", nicePath(filename), line)
	}
	return "<unknown path>"
}

func niceFuncName(pc uintptr) string {
	function := runtime.FuncForPC(pc)
	if function != nil {
		name := path.Base(function.Name())
		if i := strings.Index(name, "."); i > 0 {
			name = name[i+1:]
		}
		if strings.HasPrefix(name, "(*") {
			if i := strings.Index(name, ")"); i > 0 {
				name = name[2:i] + name[i+1:]
			}
		}
		if i := strings.LastIndex(name, ".*"); i != -1 {
			name = name[:i] + "." + name[i+2:]
		}
		if i := strings.LastIndex(name, "·"); i != -1 {
			name = name[:i] + "." + name[i+2:]
		}
		return name
	}
	return "<unknown function>"
}

// -----------------------------------------------------------------------
// Result tracker to aggregate call results.

type Result struct {
	Succeeded        int
	Failed           int
	Skipped          int
	Panicked         int
	FixturePanicked  int
	ExpectedFailures int
	Missed           int    // Not even tried to run, related to a panic in the fixture.
	RunError         error  // Houston, we've got a problem.
	WorkDir          string // If KeepWorkDir is true
}

// -----------------------------------------------------------------------
// The underlying suite runner.

type suiteRunner struct {
	suite                     interface{}
	setUpSuite, tearDownSuite *methodType
	setUpTest, tearDownTest   *methodType
	tests                     []*methodType
	runError                  error
	output                    *outputWriter
	reportedProblemLast       bool
	benchTime                 time.Duration
	benchMem                  bool
}

type RunConf struct {
	Output        io.Writer
	Stream        bool
	Verbose       bool
	Filter        string
	Benchmark     bool
	BenchmarkTime time.Duration // Defaults to 1 second
	BenchmarkMem  bool
	KeepWorkDir   bool
}

// Create a new suiteRunner able to run all methods in the given suite.
func newSuiteRunner(suite interface{}, runConf *RunConf) *suiteRunner {
	var conf RunConf
	if runConf != nil {
		conf = *runConf
	}
	if conf.Output == nil {
		conf.Output = os.Stdout
	} else {
		conf.Stream = true
	}
	if conf.Benchmark {
		conf.Verbose = true
	}

	suiteType := reflect.TypeOf(suite)
	suiteNumMethods := suiteType.NumMethod()
	suiteValue := reflect.ValueOf(suite)

	runner := &suiteRunner{
		suite:     suite,
		output:    newOutputWriter(conf.Output, conf.Stream, conf.Verbose),
		benchTime: conf.BenchmarkTime,
		benchMem:  conf.BenchmarkMem,
		tests:     make([]*methodType, 0, suiteNumMethods),
	}
	if runner.benchTime == 0 {
		runner.benchTime = 1 * time.Second
	}

	var filterRegexp *regexp.Regexp
	if conf.Filter != "" {
		regexp, err := regexp.Compile(conf.Filter)
		if err != nil {
			msg := "Bad filter expression: " + err.Error()
			runner.runError = errors.New(msg)
			return runner
		}
		filterRegexp = regexp
	}

	if conf.KeepWorkDir {
		runner.runError = errors.New("KeepWorkDir is not supported")
		return runner
	}

	for i := 0; i != suiteNumMethods; i++ {
		method := newMethod(suiteValue, i)
		switch method.Info.Name {
		case "SetUpSuite":
			runner.setUpSuite = method
		case "TearDownSuite":
			runner.tearDownSuite = method
		case "SetUpTest":
			runner.setUpTest = method
		case "TearDownTest":
			runner.tearDownTest = method
		default:
			prefix := "Test"
			if conf.Benchmark {
				prefix = "Benchmark"
			}
			if !strings.HasPrefix(method.Info.Name, prefix) {
				continue
			}
			if filterRegexp == nil || method.matches(filterRegexp) {
				runner.tests = append(runner.tests, method)
			}
		}
	}
	return runner
}

// Run all methods in the given suite.
func (runner *suiteRunner) run(t *testing.T) {
	suiteName := reflect.Indirect(reflect.ValueOf(runner.suite)).Type().Name()
	t.Run(suiteName, func(t *testing.T) {
		if runner.runError == nil && len(runner.tests) > 0 {
			if runner.checkFixtureArgs(t) {
				runner.runFixture(t, runner.setUpSuite, "", nil)
				t.Cleanup(func() {
					runner.runFixture(t, runner.tearDownSuite, "", nil)
				})

				for i := 0; i != len(runner.tests); i++ {
					runner.forkTest(t, runner.tests[i])
				}
			}
		}
	})
}

func (runner *suiteRunner) newC(t *testing.T, method *methodType, kind funcKind, testName string, logb *logger) *C {
	var logw io.Writer
	if runner.output.Stream {
		logw = runner.output
	}
	if logb == nil {
		logb = new(logger)
	}

	return &C{
		T:         t,
		method:    method,
		kind:      kind,
		testName:  testName,
		logb:      logb,
		logw:      logw,
		done:      make(chan *C, 1),
		timer:     timer{benchTime: runner.benchTime},
		startTime: time.Now(),
		benchMem:  runner.benchMem,
	}
}

// Create a call object with the given suite method, and fork a
// goroutine with the provided dispatcher for running it.
func (runner *suiteRunner) forkCall(t *testing.T, method *methodType, kind funcKind, testName string, logb *logger, dispatcher func(c *C)) {
	t.Run(testName, func(t *testing.T) {
		c := runner.newC(t, method, kind, testName, logb)
		dispatcher(c)
	})
}

// Runs a fixture call synchronously.  The fixture will still be run in a
// goroutine like all suite methods, but this method will not return
// while the fixture goroutine is not done, because the fixture must be
// run in a desired order.
func (runner *suiteRunner) runFixture(t *testing.T, method *methodType, testName string, logb *logger) {
	if method != nil {
		c := runner.newC(t, method, fixtureKd, testName, logb)
		c.method.Call([]reflect.Value{reflect.ValueOf(c)})
	}
}

// Run the suite test method, together with the test-specific fixture,
// asynchronously.
func (runner *suiteRunner) forkTest(t *testing.T, method *methodType) {
	testName := method.String()
	runner.forkCall(t, method, testKd, testName, nil, func(c *C) {
		c.T.Cleanup(func() {
			runner.runFixture(c.T, runner.tearDownTest, testName, nil)
		})
		defer c.StopTimer()
		benchN := 1
		for {
			runner.runFixture(c.T, runner.setUpTest, testName, c.logb)
			mt := c.method.Type()
			if mt.NumIn() != 1 || mt.In(0) != reflect.TypeOf(c) {
				// Rather than a plain panic, provide a more helpful message when
				// the argument type is incorrect.
				c.logArgPanic(c.method, "*check.C")
				return
			}
			if strings.HasPrefix(c.method.Info.Name, "Test") {
				c.ResetTimer()
				c.StartTimer()
				c.method.Call([]reflect.Value{reflect.ValueOf(c)})
				return
			}
			if !strings.HasPrefix(c.method.Info.Name, "Benchmark") {
				panic("unexpected method prefix: " + c.method.Info.Name)
			}

			runtime.GC()
			c.N = benchN
			c.ResetTimer()
			c.StartTimer()
			c.method.Call([]reflect.Value{reflect.ValueOf(c)})
			c.StopTimer()
			if c.duration >= c.benchTime || benchN >= 1e9 {
				return
			}
			perOpN := int(1e9)
			if c.nsPerOp() != 0 {
				perOpN = int(c.benchTime.Nanoseconds() / c.nsPerOp())
			}

			// Logic taken from the stock testing package:
			// - Run more iterations than we think we'll need for a second (1.5x).
			// - Don't grow too fast in case we had timing errors previously.
			// - Be sure to run at least one more than last time.
			benchN = max(min(perOpN+perOpN/2, 100*benchN), benchN+1)
			benchN = roundUp(benchN)
		}
	})
}

// Verify if the fixture arguments are *check.C.  In case of errors,
// log the error as a panic in the fixture method call, and return false.
func (runner *suiteRunner) checkFixtureArgs(t *testing.T) bool {
	succeeded := true
	argType := reflect.TypeOf(&C{})
	for _, method := range []*methodType{runner.setUpSuite, runner.tearDownSuite, runner.setUpTest, runner.tearDownTest} {
		if method != nil {
			mt := method.Type()
			if mt.NumIn() != 1 || mt.In(0) != argType {
				t.Errorf("%s: first argument is not *check.C", niceFuncName(method.PC()))
				succeeded = false
			}
		}
	}
	return succeeded
}
