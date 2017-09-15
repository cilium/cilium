/*
Copyright 2015 Gravitational, Inc.

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

package trace

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"

	"golang.org/x/net/context"
	. "gopkg.in/check.v1"
)

func TestTrace(t *testing.T) { TestingT(t) }

type TraceSuite struct {
}

var _ = Suite(&TraceSuite{})

func (s *TraceSuite) TestEmpty(c *C) {
	c.Assert(DebugReport(nil), Equals, "")
	c.Assert(UserMessage(nil), Equals, "")
}

func (s *TraceSuite) TestWrap(c *C) {
	testErr := &TestError{Param: "param"}
	err := Wrap(Wrap(testErr))

	c.Assert(line(DebugReport(err)), Matches, ".*trace_test.go.*")
	c.Assert(line(UserMessage(err)), Not(Matches), ".*trace_test.go.*")
}

func (s *TraceSuite) TestOrigError(c *C) {
	testErr := fmt.Errorf("some error")
	err := Wrap(Wrap(testErr))
	c.Assert(err.OrigError(), Equals, testErr)
}

func (s *TraceSuite) TestIsEOF(c *C) {
	c.Assert(IsEOF(io.EOF), Equals, true)
	c.Assert(IsEOF(Wrap(io.EOF)), Equals, true)
}

func (s *TraceSuite) TestWrapMessage(c *C) {
	testErr := fmt.Errorf("description")

	err := Wrap(testErr)

	SetDebug(true)
	c.Assert(line(err.Error()), Matches, ".*trace_test.go.*")
	c.Assert(line(err.Error()), Matches, ".*description.*")

	SetDebug(false)
	c.Assert(line(err.Error()), Not(Matches), ".*trace_test.go.*")
	c.Assert(line(err.Error()), Matches, ".*description.*")
}

func (s *TraceSuite) TestWrapUserMessage(c *C) {
	testErr := fmt.Errorf("description")

	err := Wrap(testErr, "user message")
	c.Assert(line(UserMessage(err)), Equals, "user message")

	err = Wrap(err, "user message 2")
	c.Assert(line(UserMessage(err)), Equals, "user message, user message 2")
}

func (s *TraceSuite) TestWrapNil(c *C) {
	err1 := Wrap(nil, "message: %v", "extra")
	c.Assert(err1, IsNil)

	var err2 error
	err2 = nil

	err3 := Wrap(err2)
	c.Assert(err3, IsNil)

	err4 := Wrap(err3)
	c.Assert(err4, IsNil)
}

func (s *TraceSuite) TestWrapStdlibErrors(c *C) {
	c.Assert(IsNotFound(os.ErrNotExist), Equals, true)
}

func (s *TraceSuite) TestLogFormatter(c *C) {

	for _, f := range []log.Formatter{&TextFormatter{}, &JSONFormatter{}} {
		log.SetFormatter(f)

		// check case with global Infof
		buf := &bytes.Buffer{}
		log.SetOutput(buf)
		log.Infof("hello")
		c.Assert(line(buf.String()), Matches, ".*trace_test.go.*")

		// check case with embedded Infof
		buf = &bytes.Buffer{}
		log.SetOutput(buf)
		log.WithFields(log.Fields{"a": "b"}).Infof("hello")
		c.Assert(line(buf.String()), Matches, ".*trace_test.go.*")
	}
}

func (s *TraceSuite) TestGenericErrors(c *C) {
	testCases := []struct {
		Err        error
		Predicate  func(error) bool
		StatusCode int
	}{
		{
			Err:        NotFound("not found"),
			Predicate:  IsNotFound,
			StatusCode: http.StatusNotFound,
		},
		{
			Err:        AlreadyExists("already exists"),
			Predicate:  IsAlreadyExists,
			StatusCode: http.StatusConflict,
		},
		{
			Err:        BadParameter("is bad"),
			Predicate:  IsBadParameter,
			StatusCode: http.StatusBadRequest,
		},
		{
			Err:        CompareFailed("is bad"),
			Predicate:  IsCompareFailed,
			StatusCode: http.StatusPreconditionFailed,
		},
		{
			Err:        AccessDenied("denied"),
			Predicate:  IsAccessDenied,
			StatusCode: http.StatusForbidden,
		},
		{
			Err:        ConnectionProblem(nil, "prob"),
			Predicate:  IsConnectionProblem,
			StatusCode: http.StatusRequestTimeout,
		},
		{
			Err:        LimitExceeded("limit exceeded"),
			Predicate:  IsLimitExceeded,
			StatusCode: statusTooManyRequests,
		},
	}

	for i, testCase := range testCases {
		comment := Commentf("test case #%v", i+1)
		SetDebug(true)
		err := testCase.Err

		t := err.(*TraceErr)
		c.Assert(len(t.Traces), Not(Equals), 0, comment)
		c.Assert(line(err.Error()), Matches, "*.trace_test.go.*", comment)
		c.Assert(testCase.Predicate(err), Equals, true, comment)

		w := newTestWriter()
		WriteError(w, err)
		outerr := ReadError(w.StatusCode, w.Body)
		c.Assert(testCase.Predicate(outerr), Equals, true, comment)
		t = outerr.(*TraceErr)
		c.Assert(len(t.Traces), Not(Equals), 0, comment)

		SetDebug(false)
		w = newTestWriter()
		WriteError(w, err)
		outerr = ReadError(w.StatusCode, w.Body)
		c.Assert(testCase.Predicate(outerr), Equals, true, comment)
	}
}

// Make sure we write some output produced by standard errors
func (s *TraceSuite) TestWriteExternalErrors(c *C) {
	err := fmt.Errorf("snap!")

	SetDebug(true)
	w := newTestWriter()
	WriteError(w, err)
	c.Assert(w.StatusCode, Equals, http.StatusInternalServerError)
	c.Assert(strings.Replace(string(w.Body), "\n", "", -1), Matches, "*.snap.*")

	SetDebug(false)
	w = newTestWriter()
	WriteError(w, err)
	c.Assert(w.StatusCode, Equals, http.StatusInternalServerError)
	c.Assert(strings.Replace(string(w.Body), "\n", "", -1), Matches, "*.snap.*")
}

type netError struct {
}

func (e *netError) Error() string   { return "net" }
func (e *netError) Timeout() bool   { return true }
func (e *netError) Temporary() bool { return true }

func (s *TraceSuite) TestConvert(c *C) {
	err := ConvertSystemError(&netError{})
	c.Assert(IsConnectionProblem(err), Equals, true, Commentf("failed to detect network error"))
}

func (s *TraceSuite) TestAggregates(c *C) {
	err1 := Errorf("failed one")
	err2 := Errorf("failed two")
	err := NewAggregate(err1, err2)
	c.Assert(IsAggregate(err), Equals, true)
	agg := Unwrap(err).(Aggregate)
	c.Assert(agg.Errors(), DeepEquals, []error{err1, err2})
	c.Assert(err.Error(), DeepEquals, "failed one, failed two")
}

func (s *TraceSuite) TestErrorf(c *C) {
	err := Errorf("error")
	c.Assert(line(DebugReport(err)), Matches, "*.trace_test.go.*")
	c.Assert(line(err.(*TraceErr).Message), Equals, "error")
}

func (s *TraceSuite) TestAggregateConvertsToCommonErrors(c *C) {
	testCases := []struct {
		Err                error
		Predicate          func(error) bool
		RoundtripPredicate func(error) bool
		StatusCode         int
	}{
		{
			// Aggregate unwraps to first aggregated error
			Err: NewAggregate(BadParameter("invalid value of foo"),
				LimitExceeded("limit exceeded")),
			Predicate:          IsAggregate,
			RoundtripPredicate: IsBadParameter,
			StatusCode:         http.StatusBadRequest,
		},
		{
			// Nested aggregate unwraps recursively
			Err: NewAggregate(NewAggregate(BadParameter("invalid value of foo"),
				LimitExceeded("limit exceeded"))),
			Predicate:          IsAggregate,
			RoundtripPredicate: IsBadParameter,
			StatusCode:         http.StatusBadRequest,
		},
	}
	for i, testCase := range testCases {
		comment := Commentf("test case #%v", i+1)
		SetDebug(true)
		err := testCase.Err

		c.Assert(line(err.Error()), Matches, "*.trace_test.go.*", comment)
		c.Assert(testCase.Predicate(err), Equals, true, comment)

		w := newTestWriter()
		WriteError(w, err)
		outerr := ReadError(w.StatusCode, w.Body)
		c.Assert(testCase.RoundtripPredicate(outerr), Equals, true, comment)

		t := outerr.(*TraceErr)
		c.Assert(len(t.Traces), Not(Equals), 0, comment)

		SetDebug(false)
		w = newTestWriter()
		WriteError(w, err)
		outerr = ReadError(w.StatusCode, w.Body)
		c.Assert(testCase.RoundtripPredicate(outerr), Equals, true, comment)
	}
}

func (s *TraceSuite) TestAggregateThrowAwayNils(c *C) {
	err := NewAggregate(fmt.Errorf("error1"), nil, fmt.Errorf("error2"))
	c.Assert(err.Error(), Not(Matches), ".*nil.*")
}

func (s *TraceSuite) TestAggregateAllNils(c *C) {
	c.Assert(NewAggregate(nil, nil, nil), IsNil)
}

func (s *TraceSuite) TestAggregateFromChannel(c *C) {
	errCh := make(chan error, 3)
	errCh <- fmt.Errorf("Snap!")
	errCh <- fmt.Errorf("BAM")
	errCh <- fmt.Errorf("omg")
	close(errCh)
	err := NewAggregateFromChannel(errCh, context.Background())
	c.Assert(err.Error(), Matches, ".*Snap!.*")
	c.Assert(err.Error(), Matches, ".*BAM.*")
	c.Assert(err.Error(), Matches, ".*omg.*")
}

func (s *TraceSuite) TestAggregateFromChannelCancel(c *C) {
	errCh := make(chan error, 3)
	errCh <- fmt.Errorf("Snap!")
	errCh <- fmt.Errorf("BAM")
	errCh <- fmt.Errorf("omg")
	ctx, cancel := context.WithCancel(context.Background())
	// we never closed the channel so we just need to make sure
	// the function exits when we cancel it
	cancel()
	NewAggregateFromChannel(errCh, ctx)
}

type TestError struct {
	Traces
	Param string
}

func (n *TestError) Error() string {
	return fmt.Sprintf("TestError(param=%v,trace=%v)", n.Param, n.Traces)
}

func (n *TestError) OrigError() error {
	return n
}

func newTestWriter() *testWriter {
	return &testWriter{
		H: make(http.Header),
	}
}

type testWriter struct {
	H          http.Header
	Body       []byte
	StatusCode int
}

func (tw *testWriter) Header() http.Header {
	return tw.H
}

func (tw *testWriter) Write(body []byte) (int, error) {
	tw.Body = body
	return len(tw.Body), nil
}

func (tw *testWriter) WriteHeader(code int) {
	tw.StatusCode = code
}

func line(s string) string {
	return strings.Replace(s, "\n", "", -1)
}
