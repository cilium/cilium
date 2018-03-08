/*
Copyright 2017 Mirantis

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

package ginkgoext

import (
	"bytes"
	"flag"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/config"
)

type scope struct {
	parent       *scope
	children     []*scope
	counter      int32
	before       []func()
	after        []func()
	started      int32
	failed       bool
	normalTests  int
	focusedTests int
	focused      bool
}

var (
	currentScope        = &scope{}
	rootScope           = currentScope
	countersInitialized bool

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
	By                                    = ginkgo.By
	JustBeforeEach                        = ginkgo.JustBeforeEach
	BeforeSuite                           = ginkgo.BeforeSuite
	AfterSuite                            = ginkgo.AfterSuite
	Skip                                  = ginkgo.Skip
	Fail                                  = ginkgo.Fail
	CurrentGinkgoTestDescription          = ginkgo.CurrentGinkgoTestDescription
	GinkgoRecover                         = ginkgo.GinkgoRecover
	GinkgoT                               = ginkgo.GinkgoT
	RunSpecs                              = ginkgo.RunSpecs
	RunSpecsWithCustomReporters           = ginkgo.RunSpecsWithCustomReporters
	RunSpecsWithDefaultAndCustomReporters = ginkgo.RunSpecsWithDefaultAndCustomReporters
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

// AfterEach runs the function after each test in context
func AfterEach(body interface{}, timeout ...float64) bool {
	if currentScope == nil {
		return ginkgo.AfterEach(body, timeout...)
	}
	cs := currentScope
	after := func() {
		if cs.counter == 0 && cs.after != nil {
			for _, after := range cs.after {
				after()
			}
		}
	}
	return ginkgo.AfterEach(applyAdvice(body, nil, after), timeout...)
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
			atomic.AddInt32(&cs.counter, -1)
			cs = cs.parent
		}
	}
	return applyAdvice(f, nil, after)
}

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
