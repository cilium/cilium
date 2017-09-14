package logrus_fluent

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/Sirupsen/logrus"
)

var (
	// used for persistent mock server
	data     = make(chan string)
	mockPort int
)

const (
	defaultLoopCount = 10 // assertion count
	testHOST         = "localhost"
)

// test data and assertion
const (
	fieldValue       = "data"
	assertFieldValue = "value\xa4data"

	fieldTag                  = "debug.test"
	assertFieldTag            = "\xa3tag\xaadebug.test"
	assertFieldTagAsFluentTag = "\x94\xaadebug.test\xd2"

	fieldMessage       = "FieldMessage"
	assertFieldMessage = "\xa7message\xacFieldMessage"

	entryMessage                  = "MyEntryMessage"
	assertEntryMessage            = "\xa7message\xaeMyEntryMessage"
	assertEntryMessageAsFluentTag = "\x94\xaeMyEntryMessage\xd2"

	staticTag                  = "STATIC_TAG"
	assertStaticTag            = "\xa3tag\xaaSTATIC_TAG"
	assertStaticTagAsFluentTag = "\x94\xaaSTATIC_TAG\xd2"
)

func TestNew(t *testing.T) {
	_, port := newMockServer(t, nil)
	hook, err := New(testHOST, port)
	switch {
	case err != nil:
		t.Errorf("error on New: %s", err.Error())
	case hook == nil:
		t.Errorf("hook should not be nil")
	case len(hook.levels) != len(defaultLevels):
		t.Errorf("hook.levels should be defaultLevels")
	}
}

func TestNewHook(t *testing.T) {
	const testPort = -1
	hook := NewHook(testHOST, testPort)
	switch {
	case hook == nil:
		t.Errorf("hook should not be nil")
	case hook.host != testHOST:
		t.Errorf("hook.host should be %s, but %s", testHOST, hook.host)
	case hook.port != testPort:
		t.Errorf("hook.port should be %d, but %d", testPort, hook.port)
	case len(hook.levels) != len(defaultLevels):
		t.Errorf("hook.levels should be defaultLevels")
	}
}

func TestLevels(t *testing.T) {
	hook := FluentHook{}

	levels := hook.Levels()
	if levels != nil {
		t.Errorf("hook.Levels() should be nil, but %v", levels)
	}

	hook.levels = []logrus.Level{logrus.WarnLevel}
	levels = hook.Levels()
	switch {
	case levels == nil:
		t.Errorf("hook.Levels() should not be nil")
	case len(levels) != 1:
		t.Errorf("hook.Levels() should have 1 length")
	case levels[0] != logrus.WarnLevel:
		t.Errorf("hook.Levels() should have logrus.WarnLevel")
	}
}

func TestSetLevels(t *testing.T) {
	hook := FluentHook{}

	levels := hook.levels
	if levels != nil {
		t.Errorf("hook.levels should be nil, but %v", levels)
	}

	hook.SetLevels([]logrus.Level{logrus.WarnLevel})
	levels = hook.levels
	switch {
	case levels == nil:
		t.Errorf("hook.levels should not be nil")
	case len(levels) != 1:
		t.Errorf("hook.levels should have 1 length")
	case levels[0] != logrus.WarnLevel:
		t.Errorf("hook.levels should have logrus.WarnLevel")
	}

	hook.SetLevels(nil)
	levels = hook.levels
	if levels != nil {
		t.Errorf("hook.levels should be nil, but %v", levels)
	}
}

func TestTag(t *testing.T) {
	hook := FluentHook{}

	tag := hook.Tag()
	if tag != "" {
		t.Errorf("hook.Tag() should be empty, but %s", tag)
	}

	defaultTag := staticTag
	hook.tag = &defaultTag
	tag = hook.Tag()
	switch {
	case tag == "":
		t.Errorf("hook.Tag() should not be empty")
	case tag != defaultTag:
		t.Errorf("hook.Tag() should be %s, but %s", defaultTag, tag)
	}
}

func TestSetTag(t *testing.T) {
	hook := FluentHook{}

	tag := hook.tag
	if tag != nil {
		t.Errorf("hook.tag should be nil, but %s", *tag)
	}

	hook.SetTag(staticTag)
	tag = hook.tag
	switch {
	case tag == nil:
		t.Errorf("hook.tag should not be nil")
	case *tag != staticTag:
		t.Errorf("hook.tag should be %s, but %s", staticTag, *tag)
	}
}

func TestAddIgnore(t *testing.T) {
	hook := FluentHook{
		ignoreFields: make(map[string]struct{}),
	}

	list := []string{"foo", "bar", "baz"}
	for i, key := range list {
		if len(hook.ignoreFields) != i {
			t.Errorf("hook.ignoreFields has %d length, but %d", i, len(hook.ignoreFields))
			continue
		}

		hook.AddIgnore(key)
		if len(hook.ignoreFields) != i+1 {
			t.Errorf("hook.ignoreFields should be added")
			continue
		}
		for j := 0; j <= i; j++ {
			k := list[j]
			if _, ok := hook.ignoreFields[k]; !ok {
				t.Errorf("%s should be added into hook.ignoreFields", k)
				continue
			}
		}
	}
}

func TestAddFilter(t *testing.T) {
	hook := FluentHook{
		filters: make(map[string]func(interface{}) interface{}),
	}

	list := []string{"foo", "bar", "baz"}
	for i, key := range list {
		if len(hook.filters) != i {
			t.Errorf("hook.filters has %d length, but %d", i, len(hook.filters))
			continue
		}

		hook.AddFilter(key, nil)
		if len(hook.filters) != i+1 {
			t.Errorf("hook.filters should be added")
			continue
		}
		for j := 0; j <= i; j++ {
			k := list[j]
			if _, ok := hook.filters[k]; !ok {
				t.Errorf("%s should be added into hook.filters", k)
				continue
			}
		}
	}
}

func TestLogEntryMessageReceived(t *testing.T) {
	f := logrus.Fields{
		"value": fieldValue,
	}

	assertion := func(result string) {
		switch {
		case !strings.Contains(result, assertEntryMessageAsFluentTag):
			t.Errorf("message should contain fluent-tag from entry.Message")
		case !strings.Contains(result, assertFieldValue):
			t.Errorf("message should contain value from field")
		}
	}
	assertLogHook(t, f, entryMessage, assertion)

}

func TestLogEntryMessageReceivedWithTag(t *testing.T) {
	f := logrus.Fields{
		"tag":   fieldTag,
		"value": fieldValue,
	}

	assertion := func(result string) {
		switch {
		case !strings.Contains(result, assertFieldTagAsFluentTag):
			t.Errorf("message should contain fluent-tag from field")
		case !strings.Contains(result, assertFieldValue):
			t.Errorf("message should contain value from field")
		case !strings.Contains(result, assertEntryMessage):
			t.Errorf("message should contain message from entry.Message")
		}
	}
	assertLogHook(t, f, entryMessage, assertion)
}

func TestLogEntryMessageReceivedWithMessage(t *testing.T) {
	f := logrus.Fields{
		"message": fieldMessage,
		"value":   fieldValue,
	}

	assertion := func(result string) {
		switch {
		case !strings.Contains(result, assertEntryMessageAsFluentTag):
			t.Errorf("message should contain fluent-tag from entry.Message")
		case !strings.Contains(result, assertFieldValue):
			t.Errorf("message should contain value from field")
		case !strings.Contains(result, assertFieldMessage):
			t.Errorf("message should contain message from field")
		}
	}
	assertLogHook(t, f, entryMessage, assertion)
}

func TestLogEntryMessageReceivedWithTagAndMessage(t *testing.T) {
	f := logrus.Fields{
		"message": fieldMessage,
		"tag":     fieldTag,
		"value":   fieldValue,
	}

	assertion := func(result string) {
		switch {
		case !strings.Contains(result, assertFieldTagAsFluentTag):
			t.Errorf("message should contain fluent-tag from field")
		case !strings.Contains(result, assertFieldValue):
			t.Errorf("message should contain value from field")
		case !strings.Contains(result, assertFieldMessage):
			t.Errorf("message should contain message from field")
		case strings.Contains(result, entryMessage):
			t.Errorf("message should not contain entry.Message")
		}
	}
	assertLogHook(t, f, entryMessage, assertion)
}

func TestLogEntryStaticTag(t *testing.T) {
	f := logrus.Fields{
		"value": fieldValue,
	}

	assertion := func(result string) {
		switch {
		case !strings.Contains(result, assertStaticTagAsFluentTag):
			t.Errorf("message should contain fluent-tag from static tag")
		case !strings.Contains(result, assertFieldValue):
			t.Errorf("message should contain value from field")
		case !strings.Contains(result, assertEntryMessage):
			t.Errorf("message should contain message from entry.Message")
		}
	}
	assertLogHookWithStaticTag(t, f, entryMessage, assertion)
}

func TestLogEntryStaticTagWithTag(t *testing.T) {
	f := logrus.Fields{
		"tag":   fieldTag,
		"value": fieldValue,
	}

	assertion := func(result string) {
		switch {
		case !strings.Contains(result, assertStaticTagAsFluentTag):
			t.Errorf("message should contain fluent-tag from static tag")
		case !strings.Contains(result, assertFieldTag):
			t.Errorf("message should contain tag from field")
		case !strings.Contains(result, assertFieldValue):
			t.Errorf("message should contain value from field")
		case !strings.Contains(result, assertEntryMessage):
			t.Errorf("message should contain message from entry.Message")
		}
	}
	assertLogHookWithStaticTag(t, f, entryMessage, assertion)
}

func TestLogEntryStaticTagWithMessage(t *testing.T) {
	f := logrus.Fields{
		"message": fieldMessage,
		"value":   fieldValue,
	}

	assertion := func(result string) {
		switch {
		case !strings.Contains(result, assertStaticTagAsFluentTag):
			t.Errorf("message should contain fluent-tag from static tag")
		case !strings.Contains(result, assertFieldValue):
			t.Errorf("message should contain value from field")
		case strings.Contains(result, entryMessage):
			t.Errorf("message should not contain entry.Message")
		}
	}
	assertLogHookWithStaticTag(t, f, entryMessage, assertion)
}

func TestLogEntryStaticTagWithTagAndMessage(t *testing.T) {
	f := logrus.Fields{
		"message": fieldMessage,
		"tag":     fieldTag,
		"value":   fieldValue,
	}

	assertion := func(result string) {
		switch {
		case !strings.Contains(result, assertStaticTagAsFluentTag):
			t.Errorf("message should contain fluent-tag from static tag")
		case !strings.Contains(result, assertFieldValue):
			t.Errorf("message should contain value from field")
		case !strings.Contains(result, assertFieldMessage):
			t.Errorf("message should contain message from field")
		case strings.Contains(result, entryMessage):
			t.Errorf("message should not contain entry.Message")
		}
	}
	assertLogHookWithStaticTag(t, f, entryMessage, assertion)
}

func assertLogHook(t *testing.T, f logrus.Fields, message string, assertFunc func(string)) {
	assertLogMessage(t, f, message, "", assertFunc)
}

func assertLogHookWithStaticTag(t *testing.T, f logrus.Fields, message string, assertFunc func(string)) {
	assertLogMessage(t, f, message, staticTag, assertFunc)
}

func assertLogMessage(t *testing.T, f logrus.Fields, message string, tag string, assertFunc func(string)) {
	// assert brand new logger
	{
		localData := make(chan string)
		_, port := newMockServer(t, localData)
		hook := NewHook(testHOST, port)
		if tag != "" {
			hook.SetTag(tag)
		}
		logger := logrus.New()
		logger.Hooks.Add(hook)

		for i := 0; i < defaultLoopCount; i++ {
			logger.WithFields(f).Error(message)
			assertFunc(<-localData)
		}
	}

	// assert persistent logger
	{
		port := getOrCreateMockServer(t, data)
		hook, err := New(testHOST, port)
		if err != nil {
			t.Errorf("Error on NewHookWithLogger: %s", err.Error())
		}
		if tag != "" {
			hook.SetTag(tag)
		}

		logger := logrus.New()
		logger.Hooks.Add(hook)

		for i := 0; i < defaultLoopCount; i++ {
			logger.WithFields(f).Error(message)
			assertFunc(<-data)
		}
	}
}

func getOrCreateMockServer(t *testing.T, data chan string) int {
	if mockPort == 0 {
		_, mockPort = newMockServer(t, data)
	}
	return mockPort
}

func newMockServer(t *testing.T, data chan string) (net.Listener, int) {
	l, err := net.Listen("tcp", testHOST+":0")
	if err != nil {
		t.Errorf("Error listening: %s", err.Error())
	}

	count := 0
	go func() {
		for {
			count++
			conn, err := l.Accept()
			if err != nil {
				t.Errorf("Error accepting: %s", err.Error())
			}

			go handleRequest(conn, l, data)
			if count == defaultLoopCount {
				l.Close()
				return
			}
		}
	}()
	return l, l.Addr().(*net.TCPAddr).Port
}

func handleRequest(conn net.Conn, l net.Listener, data chan string) {
	r := bufio.NewReader(conn)
	for {
		b := make([]byte, 1<<10) // Read 1KB at a time
		_, err := r.Read(b)
		if err == io.EOF {
			continue
		} else if err != nil {
			fmt.Printf("Error reading from connection: %s", err)
		}
		data <- string(b)
	}
}
