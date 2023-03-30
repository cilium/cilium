// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2017 Mirantis

package ginkgoext

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/config"

	"github.com/cilium/cilium/pkg/lock"
	ciliumTestConfig "github.com/cilium/cilium/test/config"
)

type scope struct {
	parent        *scope
	children      []*scope
	counter       int32
	mutex         *lock.Mutex
	before        []func()
	after         []func()
	afterEach     []func()
	justAfterEach []func()
	afterFail     []func()
	started       int32
	failed        bool
	normalTests   int
	focusedTests  int
	focused       bool
	text          string
}

var (
	currentScope = &scope{
		text:    "EntireTestsuite",
		counter: -1,
		mutex:   &lock.Mutex{},
	}

	rootScope = currentScope

	// failEnabled for tests that have failed on JustAfterEach function we need
	// to handle differently, because `ginkgo.Fail` do a panic, and all the
	// following functions will not be called. With the WrapFailfn if the fail
	// is on any After function, will not panic, will mark the test as failed,
	// and will trigger the Fail function at the end.
	failEnabled     = true
	afterEachFailed = map[string]bool{}
	afterEachCB     = map[string]func(){}

	// We wrap various ginkgo function here to track invocations and determine
	// when to call AfterAll. When using a new ginkgo equivalent to It or
	// Measure, it may need a matching wrapper similar to wrapItFunc.

	Context                               = wrapContextFunc(ginkgo.Context, false)
	FContext                              = wrapContextFunc(ginkgo.FContext, true)
	PContext                              = wrapNilContextFunc(ginkgo.PContext)
	XContext                              = wrapNilContextFunc(ginkgo.XContext)
	Describe                              = wrapContextFunc(ginkgo.Describe, false)
	FDescribe                             = wrapContextFunc(ginkgo.FDescribe, true)
	PDescribe                             = wrapNilContextFunc(ginkgo.PDescribe)
	XDescribe                             = wrapNilContextFunc(ginkgo.XDescribe)
	It                                    = wrapItFunc(ginkgo.It, false)
	FIt                                   = wrapItFunc(ginkgo.FIt, true)
	PIt                                   = ginkgo.PIt
	XIt                                   = ginkgo.XIt
	Measure                               = wrapMeasureFunc(ginkgo.Measure, false)
	JustBeforeEach                        = ginkgo.JustBeforeEach
	BeforeSuite                           = ginkgo.BeforeSuite
	AfterSuite                            = ginkgo.AfterSuite
	Skip                                  = ginkgo.Skip
	Fail                                  = FailWithToggle
	CurrentGinkgoTestDescription          = ginkgo.CurrentGinkgoTestDescription
	GinkgoRecover                         = ginkgo.GinkgoRecover
	GinkgoT                               = ginkgo.GinkgoT
	RunSpecs                              = ginkgo.RunSpecs
	RunSpecsWithCustomReporters           = ginkgo.RunSpecsWithCustomReporters
	RunSpecsWithDefaultAndCustomReporters = ginkgo.RunSpecsWithDefaultAndCustomReporters
	GinkgoWriter                          = NewWriter(ginkgo.GinkgoWriter)
)

type Done ginkgo.Done

func init() {
	// Only use the Ginkgo options and discard all other options
	args := []string{}
	for _, arg := range os.Args[1:] {
		if strings.Contains(arg, "--ginkgo") {
			args = append(args, arg)
		}
	}

	//Get GinkgoConfig flags
	commandFlags := flag.NewFlagSet("ginkgo", flag.ContinueOnError)
	commandFlags.SetOutput(new(bytes.Buffer))

	config.Flags(commandFlags, "ginkgo", true)
	commandFlags.Parse(args)
	ciliumTestConfig.CiliumTestConfig.ParseFlags()

	if !config.DefaultReporterConfig.Succinct {
		config.DefaultReporterConfig.Verbose = true
	}
}

func (s *scope) isUnset() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return (s.counter == -1)
}

func (s *scope) isZero() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return (s.counter == 0)
}

func (s *scope) setSafely(val int) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.counter = int32(val)
}

func (s *scope) decrementSafely() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.counter--
	if s.counter < 0 {
		panic(fmt.Sprintf("ERROR: unexpected negative scope counter value: %d", s.counter))
	}
}

func CurrnetScopeCounter() int32 {
	currentScope.mutex.Lock()
	defer currentScope.mutex.Unlock()
	return currentScope.counter
}

// By allows you to better document large Its.
//
// Generally you should try to keep your Its short and to the point.  This is
// not always possible, however, especially in the context of integration tests
// that capture a particular workflow.
//
// By allows you to document such flows.  By must be called within a runnable
// node (It, BeforeEach, Measure, etc...)
// By will simply log the passed in text to the GinkgoWriter.
func By(message string, optionalValues ...interface{}) {
	if len(optionalValues) > 0 {
		message = fmt.Sprintf(message, optionalValues...)
	}
	fullmessage := fmt.Sprintf("%s STEP: %s", time.Now().Format("15:04:05"), message)
	GinkgoPrint(fullmessage)
}

// GinkgoPrint send the given message to the test writers to store it.
func GinkgoPrint(message string, optionalValues ...interface{}) {
	if len(optionalValues) > 0 {
		message = fmt.Sprintf(message, optionalValues...)
	}
	fmt.Fprintln(GinkgoWriter, message)
	fmt.Fprintln(ginkgo.GinkgoWriter, message)
}

// GetTestName returns the test Name in a single string without spaces or /
func GetTestName() string {
	testDesc := ginkgo.CurrentGinkgoTestDescription()
	name := strings.Replace(testDesc.FullTestText, " ", "_", -1)
	name = strings.Trim(name, "*")
	return strings.Replace(name, "/", "-", -1)
}

// BeforeAll runs the function once before any test in context
func BeforeAll(body func()) bool {
	if currentScope != nil {
		if body == nil {
			currentScope.before = nil
			return true
		}

		contextName := currentScope.text
		currentScope.before = append(currentScope.before, func() {
			By("Running BeforeAll block for %s", contextName)
			body()
		})
		return beforeEach(func() {})
	}

	return true
}

// AfterAll runs the function once after any test in context
func AfterAll(body func()) bool {
	if currentScope != nil {
		if body == nil {
			currentScope.before = nil
			return true
		}
		contextName := currentScope.text
		currentScope.after = append(currentScope.after, func() {
			By("Running AfterAll block for %s", contextName)
			body()
		})
		return afterEach(func() {})
	}
	return true
}

// JustAfterEach runs the function just after each test, before all AfterEeach,
// AfterFailed and AfterAll
func JustAfterEach(body func()) bool {
	if currentScope != nil {
		if body == nil {
			currentScope.before = nil
			return true
		}
		contextName := currentScope.text
		currentScope.justAfterEach = append(currentScope.justAfterEach, func() {
			By("Running JustAfterEach block for %s", contextName)
			body()
		})
		return afterEach(func() {})
	}
	return true
}

// JustAfterFailed runs the function after test and JustAfterEach if the test
// has failed and before all AfterEach
func AfterFailed(body func()) bool {
	if currentScope != nil {
		if body == nil {
			currentScope.before = nil
			return true
		}
		contextName := currentScope.text
		currentScope.afterFail = append(currentScope.afterFail, func() {
			By("Running AfterFailed block for %s", contextName)
			body()
		})
		return afterEach(func() {})
	}
	return true
}

// justAfterEachStatus map to store what `justAfterEach` functions have been
// already executed for the given test
var justAfterEachStatus map[string]bool = map[string]bool{}

// runAllJustAfterEach runs all the `scope.justAfterEach` functions for the
// given scope and parent scopes. This function make sure that all the
// `JustAfterEach` functions are called before AfterEach functions.
func runAllJustAfterEach(cs *scope, testName string) {
	if _, ok := justAfterEachStatus[testName]; ok {
		// JustAfterEach calls are already executed in the children
		return
	}

	for _, body := range cs.justAfterEach {
		body()
	}

	if cs.parent != nil {
		runAllJustAfterEach(cs.parent, testName)
	}
}

// afterEachStatus map to store what `AfterEach` functions have been
// already executed for the given test
var afterEachStatus map[string]bool = map[string]bool{}

// runAllAfterEach runs all the `scope.AfterEach` functions for the
// given scope and parent scopes. This function make sure that all the
// `AfterEach` functions are called before AfterAll functions.
func runAllAfterEach(cs *scope, testName string) {
	if _, ok := afterEachStatus[testName]; ok {
		// AfterEach calls are already executed in the children
		return
	}

	for _, body := range cs.afterEach {
		body()
	}
	if cs.parent != nil {
		runAllAfterEach(cs.parent, testName)
	}
}

// afterFailedStatus map to store what `AfterFail` functions have been
// already executed for the given test.
var afterFailedStatus map[string]bool = map[string]bool{}

func testFailed(testName string) bool {
	hasFailed, _ := afterEachFailed[testName]
	return ginkgo.CurrentGinkgoTestDescription().Failed || hasFailed
}

// TestFailed returns true if the current test has failed.
func TestFailed() bool {
	testName := ginkgo.CurrentGinkgoTestDescription().FullTestText
	return testFailed(testName)
}

// runAllAfterFail runs all the afterFail functions for the given
// scope and parent scopes. This function make sure that all the `AfterFail`
// functions are called before AfterEach.
func runAllAfterFail(cs *scope, testName string) {
	if _, ok := afterFailedStatus[testName]; ok {
		// AfterFailcalls are already executed in the children
		return
	}

	if testFailed(testName) && len(cs.afterFail) > 0 {
		GinkgoPrint("===================== TEST FAILED =====================")
		for _, body := range cs.afterFail {
			body()
		}
		GinkgoPrint("===================== Exiting AfterFailed =====================")
	}

	if cs.parent != nil {
		runAllAfterFail(cs.parent, testName)
	}
}

// RunAfterEach is a wrapper that executes all AfterEach functions that are
// stored in cs.afterEach array.
func RunAfterEach(cs *scope) {
	if cs == nil {
		return
	}

	// Decrement the test number due test or BeforeEach has been run.
	cs.decrementSafely()

	// Disabling the `ginkgo.Fail` function to avoid the panic and be able to
	// gather all the logs.
	failEnabled = false
	defer func() {
		failEnabled = true
	}()

	testName := ginkgo.CurrentGinkgoTestDescription().FullTestText

	if _, ok := afterEachFailed[testName]; !ok {
		afterEachFailed[testName] = false
	}

	runAllJustAfterEach(cs, testName)
	justAfterEachStatus[testName] = true

	runAllAfterFail(cs, testName)
	afterFailedStatus[testName] = true

	hasFailed := afterEachFailed[testName] || ginkgo.CurrentGinkgoTestDescription().Failed

	runAllAfterEach(cs, testName)
	afterEachStatus[testName] = true

	// Run the afterFailed in case that something fails on afterEach
	if hasFailed == false && afterEachFailed[testName] {
		GinkgoPrint("Something has failed on AfterEach, running AfterFailed functions")
		afterFailedStatus[testName] = false
		runAllAfterFail(cs, testName)
	}

	// Only run afterAll when all the counters are 0 and all afterEach are executed
	if cs.isZero() && cs.after != nil {
		for _, after := range cs.after {
			after()
		}
	}

	cb := afterEachCB[testName]
	if cb != nil {
		cb()
	}
}

// AfterEach runs the function after each test in context
func AfterEach(body func(), timeout ...float64) bool {
	var contextName string
	if currentScope != nil {
		contextName = currentScope.text
	}
	return afterEach(func() {
		By("Running AfterEach for block %s", contextName)
		body()
	}, timeout...)
}

func afterEach(body func(), timeout ...float64) bool {
	if currentScope == nil {
		return ginkgo.AfterEach(body, timeout...)
	}
	cs := currentScope
	result := true
	if cs.afterEach == nil {
		// If no scope, register only one AfterEach in the scope, after that
		// RunAfterEeach will run all afterEach functions registered in the
		// scope.
		fn := func() {
			RunAfterEach(cs)
		}
		result = ginkgo.AfterEach(fn, timeout...)
	}
	cs.afterEach = append(cs.afterEach, body)
	return result
}

// BeforeEach runs the function before each test in context
func BeforeEach(body func(), timeout ...float64) bool {
	var contextName string
	if currentScope != nil {
		contextName = currentScope.text
	}
	return beforeEach(func() {
		By("Running BeforeEach block for %s", contextName)
		body()
	}, timeout...)
}

func beforeEach(body interface{}, timeout ...float64) bool {
	if currentScope == nil {
		return ginkgo.BeforeEach(body, timeout...)
	}
	cs := currentScope
	before := func() {
		if atomic.CompareAndSwapInt32(&cs.started, 0, 1) && cs.before != nil {
			defer func() {
				if r := recover(); r != nil {
					cs.failed = true
					panic(r)
				}
			}()
			for _, before := range cs.before {
				before()
			}
		} else if cs.failed {
			Fail("failed due to BeforeAll failure")
		}
	}
	return ginkgo.BeforeEach(applyAdvice(body, before, nil), timeout...)
}

func wrapContextFunc(fn func(string, func()) bool, focused bool) func(string, func()) bool {
	// Scope handling must be performed in the function body
	// passed to gingko as Ginkgo now can defer calls to the given
	// function body.
	return func(text string, body func()) bool {
		return fn(text, func() {
			if currentScope == nil {
				body()
				return
			}
			newScope := &scope{
				text:    currentScope.text + " " + text,
				parent:  currentScope,
				focused: focused,
				mutex:   &lock.Mutex{},
				counter: -1,
			}
			currentScope.children = append(currentScope.children, newScope)
			currentScope = newScope
			body()
			currentScope = currentScope.parent
		})
	}
}

func wrapNilContextFunc(fn func(string, func()) bool) func(string, func()) bool {
	// Scope handling must be performed in the function body
	// passed to gingko as Ginkgo now can defer calls to the given
	// function body.
	return func(text string, body func()) bool {
		return fn(text, func() {
			oldScope := currentScope
			currentScope = nil
			body()
			currentScope = oldScope
		})
	}
}

// wrapItFunc wraps gingko.It to track invocations and correctly
// execute AfterAll. This is tracked via scope.focusedTests and .normalTests.
// This function is similar to wrapMeasureFunc.
func wrapItFunc(fn func(string, interface{}, ...float64) bool, focused bool) func(string, interface{}, ...float64) bool {
	if rootScope.isUnset() {
		rootScope.setSafely(0)
		BeforeSuite(func() {
			c, _ := calculateCounters(rootScope, false)
			rootScope.setSafely(c)
		})
	}
	return func(text string, body interface{}, timeout ...float64) bool {
		if currentScope == nil {
			return fn(text, body, timeout...)
		}
		if focused || isTestFocused(currentScope.text+" "+text) {
			currentScope.focusedTests++
		} else {
			currentScope.normalTests++
		}
		return fn(text, wrapTest(body), timeout...)
	}
}

// wrapMeasureFunc wraps gingko.Measure to track invocations and correctly
// execute AfterAll. This is tracked via scope.focusedTests and .normalTests.
// This function is similar to wrapItFunc.
func wrapMeasureFunc(fn func(text string, body interface{}, samples int) bool, focused bool) func(text string, body interface{}, samples int) bool {
	if rootScope.isUnset() {
		rootScope.setSafely(0)
		BeforeSuite(func() {
			c, _ := calculateCounters(rootScope, false)
			rootScope.setSafely(c)
		})
	}
	return func(text string, body interface{}, samples int) bool {
		if currentScope == nil {
			return fn(text, body, samples)
		}
		if focused || isTestFocused(currentScope.text+" "+text) {
			currentScope.focusedTests++
		} else {
			currentScope.normalTests++
		}
		return fn(text, wrapTest(body), samples)
	}
}

// isTestFocused checks the value of FocusString and return true if the given
// text name is focussed, returns false if the test is not focused.
func isTestFocused(text string) bool {
	if len(config.GinkgoConfig.FocusStrings) == 0 && len(config.GinkgoConfig.SkipStrings) == 0 {
		return false
	}

	var focusFilter, skipFilter *regexp.Regexp
	if len(config.GinkgoConfig.FocusStrings) != 0 {
		focusFilter = regexp.MustCompile(config.GinkgoConfig.FocusStrings[0])
	}
	if len(config.GinkgoConfig.SkipStrings) != 0 {
		skipFilter = regexp.MustCompile(config.GinkgoConfig.SkipStrings[0])
	}

	switch {
	case focusFilter != nil && skipFilter != nil:
		return focusFilter.MatchString(text) && !skipFilter.MatchString(text)
	case focusFilter != nil && skipFilter == nil:
		return focusFilter.MatchString(text)
	case focusFilter == nil && skipFilter != nil:
		return !skipFilter.MatchString(text)
	case focusFilter == nil && skipFilter == nil:
		return false
	}
	return false
}

func applyAdvice(f interface{}, before, after func()) interface{} {
	fn := reflect.ValueOf(f)
	template := func(in []reflect.Value) []reflect.Value {
		if before != nil {
			before()
		}
		if after != nil {
			defer after()
		}
		return fn.Call(in)
	}
	v := reflect.MakeFunc(fn.Type(), template)
	return v.Interface()
}

func wrapTest(f interface{}) interface{} {
	cs := currentScope
	after := func() {
		for cs != nil {
			cs = cs.parent
		}
		GinkgoPrint("=== Test Finished at %s====", time.Now().Format(time.RFC3339))
	}
	return applyAdvice(f, nil, after)
}

// calculateCounters initialises the tracking counters that determine when
// AfterAll should be called. It is not idempotent and should be guarded
// against repeated initializations.
func calculateCounters(s *scope, focusedOnly bool) (int, bool) {
	count := s.focusedTests
	haveFocused := s.focusedTests > 0
	focusedChildren := 0
	for _, child := range s.children {
		if child.focused {
			if !child.isUnset() {
				panic("unexepcted redundant recursive call")
			}
			child.setSafely(0)
			c, _ := calculateCounters(child, false)
			child.setSafely(c)
			focusedChildren += c
		}
	}
	if focusedChildren > 0 {
		haveFocused = true
		count += focusedChildren
	}
	normalChildren := 0
	for _, child := range s.children {
		if !child.focused {
			if !child.isUnset() {
				panic("unexepcted redundant recursive call")
			}
			child.setSafely(0)
			c, f := calculateCounters(child, focusedOnly || haveFocused)
			child.setSafely(c)
			if f {
				haveFocused = true
				count += c
			} else {
				normalChildren += c
			}
		}
	}
	if !focusedOnly && !haveFocused {
		count += s.normalTests + normalChildren
	}
	return count, haveFocused
}

// FailWithToggle wraps `ginkgo.Fail` function to have a option to disable the
// panic when something fails when is running on AfterEach.
func FailWithToggle(message string, callerSkip ...int) {
	GinkgoPrint("FAIL: " + message)

	if len(callerSkip) > 0 {
		callerSkip[0] = callerSkip[0] + 1
	}

	if failEnabled {
		ginkgo.Fail(message, callerSkip...)
	}

	testName := ginkgo.CurrentGinkgoTestDescription().FullTestText
	afterEachFailed[testName] = true

	afterEachCB[testName] = func() {
		ginkgo.Fail(message, callerSkip...)
	}
}

// SkipDescribeIf is a wrapper for the Describe block which is being executed
// if the given condition is NOT met.
func SkipDescribeIf(condition func() bool, text string, body func()) bool {
	if condition() {
		return It(text, func() {
			Skip("skipping due to unmet condition")
		})
	}

	return Describe(text, body)
}

// SkipContextIf is a wrapper for the Context block which is being executed
// if the given condition is NOT met.
func SkipContextIf(condition func() bool, text string, body func()) bool {
	if condition() {
		return It(text, func() {
			Skip("skipping due to unmet condition")
		})
	}

	return Context(text, body)
}

// SkipItIf executes the given body if the given condition is NOT met.
func SkipItIf(condition func() bool, text string, body func(), timeout ...float64) bool {
	if condition() {
		return It(text, func() {
			Skip("skipping due to unmet condition")
		})
	}

	return It(text, body, timeout...)
}

// Failf calls Fail with a formatted string
func Failf(msg string, args ...interface{}) {
	Fail(fmt.Sprintf(msg, args...))
}
