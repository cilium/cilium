/*
 * Copyright 2018-2019 Authors of Cilium
 * Copyright 2017 Mirantis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
)

type scope struct {
	parent        *scope
	children      []*scope
	counter       int32
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
}

var (
	currentScope = &scope{}
	rootScope    = currentScope
	// countersInitialized protects repeat calls of calculate counters on
	// rootScope. This relies on ginkgo being single-threaded to set the value
	// safely.
	countersInitialized bool

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
	fullmessage := fmt.Sprintf("STEP: %s", message)
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
		currentScope.before = append(currentScope.before, body)
		return BeforeEach(func() {})
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
		currentScope.after = append(currentScope.after, body)
		return AfterEach(func() {})
	}
	return true
}

//JustAfterEach runs the function just after each test, before all AfterEeach,
//AfterFailed and AfterAll
func JustAfterEach(body func()) bool {
	if currentScope != nil {
		if body == nil {
			currentScope.before = nil
			return true
		}
		currentScope.justAfterEach = append(currentScope.justAfterEach, body)
		return AfterEach(func() {})
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
		currentScope.afterFail = append(currentScope.afterFail, body)
		return AfterEach(func() {})
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
	atomic.AddInt32(&cs.counter, -1)

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
	after := func() {
		if cs.counter == 0 && cs.after != nil {
			for _, after := range cs.after {
				after()
			}
		}
	}
	after()

	cb := afterEachCB[testName]
	if cb != nil {
		cb()
	}
}

// AfterEach runs the function after each test in context
func AfterEach(body func(), timeout ...float64) bool {
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
func BeforeEach(body interface{}, timeout ...float64) bool {
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
	return func(text string, body func()) bool {
		if currentScope == nil {
			return fn(text, body)
		}
		newScope := &scope{parent: currentScope, focused: focused}
		currentScope.children = append(currentScope.children, newScope)
		currentScope = newScope
		res := fn(text, body)
		currentScope = currentScope.parent
		return res
	}
}

func wrapNilContextFunc(fn func(string, func()) bool) func(string, func()) bool {
	return func(text string, body func()) bool {
		oldScope := currentScope
		currentScope = nil
		res := fn(text, body)
		currentScope = oldScope
		return res
	}
}

// wrapItFunc wraps gingko.Measure to track invocations and correctly
// execute AfterAll. This is tracked via scope.focusedTests and .normalTests.
// This function is similar to wrapMeasureFunc.
func wrapItFunc(fn func(string, interface{}, ...float64) bool, focused bool) func(string, interface{}, ...float64) bool {
	if !countersInitialized {
		countersInitialized = true
		BeforeSuite(func() {
			calculateCounters(rootScope, false)
		})
	}
	return func(text string, body interface{}, timeout ...float64) bool {
		if currentScope == nil {
			return fn(text, body, timeout...)
		}
		if focused || isTestFocussed(text) {
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
	if !countersInitialized {
		countersInitialized = true
		BeforeSuite(func() {
			calculateCounters(rootScope, false)
		})
	}
	return func(text string, body interface{}, samples int) bool {
		if currentScope == nil {
			return fn(text, body, samples)
		}
		if focused || isTestFocussed(text) {
			currentScope.focusedTests++
		} else {
			currentScope.normalTests++
		}
		return fn(text, wrapTest(body), samples)
	}
}

// isTestFocussed checks the value of FocusString and return true if the given
// text name is focussed, returns false if the test is not focussed.
func isTestFocussed(text string) bool {
	if config.GinkgoConfig.FocusString == "" {
		return false
	}

	focusFilter := regexp.MustCompile(config.GinkgoConfig.FocusString)
	return focusFilter.Match([]byte(text))
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
	var focusedChildren int
	for _, child := range s.children {
		if child.focused {
			c, _ := calculateCounters(child, false)
			focusedChildren += c
		}
	}
	if focusedChildren > 0 {
		haveFocused = true
		count += focusedChildren
	}
	var normalChildren int
	for _, child := range s.children {
		if !child.focused {
			c, f := calculateCounters(child, focusedOnly || haveFocused)
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
	s.counter = int32(count)
	return count, haveFocused
}

// FailWithToggle wraps `ginkgo.Fail` function to have a option to disable the
// panic when something fails when is running on AfterEach.
func FailWithToggle(message string, callerSkip ...int) {

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
func SkipItIf(condition func() bool, text string, body func()) bool {
	if condition() {
		return It(text, func() {
			Skip("skipping due to unmet condition")
		})
	}

	return It(text, body)
}

// Failf calls Fail with a formatted string
func Failf(msg string, args ...interface{}) {
	Fail(fmt.Sprintf(msg, args...))
}
