package logrustash

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/Sirupsen/logrus"
)

func TestLegostashHook(t *testing.T) {
	type Expct struct {
		appName          string
		hookOnlyPrefix   string
		alwaysSentFields logrus.Fields
	}
	tt := []struct {
		expected Expct
		initFunc func() (*Hook, error)
	}{
		{Expct{"bla", "", nil}, func() (*Hook, error) {
			return NewHook("udp", "localhost:9999", "bla")
		}},
		{Expct{"bzz", "", nil}, func() (*Hook, error) {
			udpConn, err := net.Dial("udp", "localhost:9999")
			if err != nil {
				return nil, err
			}
			return NewHookWithConn(udpConn, "bzz")
		}},
		{Expct{"blk", "", logrus.Fields{"id": 1}}, func() (*Hook, error) {
			return NewHookWithFields("udp", "localhost:9999", "blk", logrus.Fields{"id": 1})
		}},
		{Expct{"prefix", "-->", logrus.Fields{"id": 1}}, func() (*Hook, error) {
			return NewHookWithFieldsAndPrefix("udp", "localhost:9999", "prefix", logrus.Fields{"id": 1}, "-->")
		}},
		{Expct{"fieldsconn", "", logrus.Fields{"id": 5}}, func() (*Hook, error) {
			udpConn, err := net.Dial("udp", "localhost:9999")
			if err != nil {
				return nil, err
			}
			return NewHookWithFieldsAndConn(udpConn, "fieldsconn", logrus.Fields{"id": 5})
		}},
		{Expct{"zz", "~~>", logrus.Fields{"id": "bal"}}, func() (*Hook, error) {
			udpConn, err := net.Dial("udp", "localhost:9999")
			if err != nil {
				return nil, err
			}
			return NewHookWithFieldsAndConnAndPrefix(udpConn, "zz", logrus.Fields{"id": "bal"}, "~~>")
		}},
	}

	for _, te := range tt {
		h, err := te.initFunc()
		if err != nil {
			t.Error(err)
		}
		if h == nil {
			t.Error("expected hook to be not nil")
		}

		if h.conn == nil {
			t.Error("expected conn to be not nil")
		}
		if h.appName != te.expected.appName {
			t.Errorf("expected appName to be '%s' but got '%s'", te.expected.appName, h.appName)
		}
		if h.alwaysSentFields == nil {
			t.Error("expected alwaysSentFields to be not nil")
		}
		if te.expected.alwaysSentFields != nil && !reflect.DeepEqual(te.expected.alwaysSentFields, h.alwaysSentFields) {
			t.Errorf("expected alwaysSentFields to be '%v' but got '%v'", te.expected.alwaysSentFields, h.alwaysSentFields)
		}
		if h.hookOnlyPrefix != te.expected.hookOnlyPrefix {
			t.Error("expected hookOnlyPrefix to be an empty string")
		}
	}
}

func TestNewFiltering(t *testing.T) {
	type Expct struct {
		prefix  string
		appName string
	}
	tt := []struct {
		expected Expct
		initFunc func() *Hook
	}{
		{Expct{"", ""}, func() *Hook {
			return NewFilterHook()
		}},
		{Expct{"~~~>", ""}, func() *Hook {
			return NewFilterHookWithPrefix("~~~>")
		}},
	}

	for _, te := range tt {
		h := te.initFunc()
		if h.conn != nil {
			t.Error("expected conn to be nil")
		}
		if h.alwaysSentFields == nil {
			t.Error("expected alwaysSentFields to be not nil")
		}
		if h.hookOnlyPrefix != te.expected.prefix {
			t.Errorf("expected prefix to be '%s' but got '%s'", te.expected.prefix, h.hookOnlyPrefix)
		}
	}
}

func TestSettingAttributes(t *testing.T) {
	tt := []struct {
		setFunc   func(*Hook)
		expctFunc func(*Hook) error
	}{
		{func(h *Hook) {
			h.WithPrefix("mprefix1")
		}, func(h *Hook) error {
			if h.hookOnlyPrefix != "mprefix1" {
				return fmt.Errorf("expected hookOnlyPrefix to be '%s' but got '%s'", "mprefix1", h.hookOnlyPrefix)
			}
			return nil
		}},
		{func(h *Hook) {
			h.WithField("name", "muha")
		}, func(h *Hook) error {
			nField := logrus.Fields{"name": "muha"}
			if !reflect.DeepEqual(h.alwaysSentFields, nField) {
				return fmt.Errorf("expected hookOnlyPrefix to be '%s' but got '%s'", nField, h.hookOnlyPrefix)
			}
			return nil
		}},
		{func(h *Hook) {
			h.WithFields(logrus.Fields{"filename": "app.log", "owner": "mick"})
		}, func(h *Hook) error {
			nField := logrus.Fields{"name": "test-me!", "filename": "app.log", "owner": "mick"}
			if !reflect.DeepEqual(h.alwaysSentFields, nField) {
				return fmt.Errorf("expected hookOnlyPrefix to be '%s' but got '%s'", nField, h.hookOnlyPrefix)
			}
			return nil
		}},
	}

	for _, te := range tt {
		hook := NewFilterHook()
		hook.alwaysSentFields = logrus.Fields{"name": "test-me!"}
		te.setFunc(hook)
		if err := te.expctFunc(hook); err != nil {
			t.Error(err)
		}
	}
}

func TestFilterHookOnly(t *testing.T) {
	tt := []struct {
		entry    *logrus.Entry
		prefix   string
		expected logrus.Fields
	}{
		{&logrus.Entry{Data: logrus.Fields{"name": "slimshady"}}, "", logrus.Fields{"name": "slimshady"}},
		{&logrus.Entry{Data: logrus.Fields{"_name": "slimshady", "nick": "blabla"}}, "_", logrus.Fields{"nick": "blabla"}},
	}

	for _, te := range tt {
		hook := NewFilterHookWithPrefix(te.prefix)
		hook.filterHookOnly(te.entry)
		if !reflect.DeepEqual(te.entry.Data, te.expected) {
			t.Errorf("expected entry data to be '%v' but got '%v'", te.expected, te.entry.Data)
		}
	}
}

type AddrMock struct {
}

func (a AddrMock) Network() string {
	return ""
}

func (a AddrMock) String() string {
	return ""
}

type ConnMock struct {
	buff *bytes.Buffer
}

func (c ConnMock) Read(b []byte) (int, error) {
	return c.buff.Read(b)
}

func (c ConnMock) Write(b []byte) (int, error) {
	return c.buff.Write(b)
}

func (c ConnMock) Close() error {
	return nil
}

func (c ConnMock) LocalAddr() net.Addr {
	return AddrMock{}
}

func (c ConnMock) RemoteAddr() net.Addr {
	return AddrMock{}
}

func (c ConnMock) SetDeadline(t time.Time) error {
	return nil
}

func (c ConnMock) SetReadDeadline(t time.Time) error {
	return nil
}

func (c ConnMock) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestFire(t *testing.T) {
	conn := ConnMock{buff: bytes.NewBufferString("")}
	hook := &Hook{
		conn:             conn,
		appName:          "fire_test",
		alwaysSentFields: logrus.Fields{"test-name": "fire-test", "->ignore": "haaa", "override": "no"},
		hookOnlyPrefix:   "->",
	}
	entry := &logrus.Entry{
		Message: "hello world!",
		Data:    logrus.Fields{"override": "yes"},
		Level:   logrus.DebugLevel,
	}
	if err := hook.Fire(entry); err != nil {
		t.Error(err)
	}
	var res map[string]string
	if err := json.NewDecoder(conn.buff).Decode(&res); err != nil {
		t.Error(err)
	}
	expected := map[string]string{
		"@timestamp": "0001-01-01T00:00:00Z",
		"@version":   "1",
		"ignore":     "haaa",
		"level":      "debug",
		"message":    "hello world!",
		"override":   "yes",
		"test-name":  "fire-test",
		"type":       "fire_test",
	}
	if !reflect.DeepEqual(expected, res) {
		t.Errorf("expected message to be '%v' but got '%v'", expected, res)
	}
}

func TestFireFilterHook(t *testing.T) {
	hook := &Hook{
		appName:          "fire_hook_test",
		alwaysSentFields: logrus.Fields{"test-name": "fire-test-hook", "_ignore": "haaa", "override": "no"},
		hookOnlyPrefix:   "_",
	}
	entry := &logrus.Entry{
		Message: "hello world!",
		Data:    logrus.Fields{"override": "yes"},
		Level:   logrus.DebugLevel,
	}
	if err := hook.Fire(entry); err != nil {
		t.Error(err)
	}
	expected := &logrus.Entry{
		Message: "hello world!",
		Data:    logrus.Fields{"test-name": "fire-test-hook", "override": "yes"},
		Level:   logrus.DebugLevel,
	}

	if !reflect.DeepEqual(expected, entry) {
		t.Errorf("expected message to be '%v' but got '%v'", expected, entry)
	}
}

func TestLevels(t *testing.T) {
	hook := &Hook{}
	expected := []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
		logrus.WarnLevel,
		logrus.InfoLevel,
		logrus.DebugLevel,
	}
	res := hook.Levels()
	if !reflect.DeepEqual(expected, res) {
		t.Errorf("expected levels to be '%v' but got '%v'", expected, res)
	}

}

func TestLogstashTimeStampFormat(t *testing.T) {
	conn := ConnMock{buff: bytes.NewBufferString("")}
	hook := &Hook{
		conn:       conn,
		TimeFormat: time.Kitchen,
	}
	fTime := time.Date(2009, time.November, 10, 3, 4, 0, 0, time.UTC)
	if err := hook.Fire(&logrus.Entry{Time: fTime}); err != nil {
		t.Errorf("expected fire to not return error: %s", err)
	}
	var res map[string]string
	if err := json.NewDecoder(conn.buff).Decode(&res); err != nil {
		t.Error(err)
	}
	if value, ok := res["@timestamp"]; !ok {
		t.Error("expected result to have '@timestamp'")
	} else if value != "3:04AM" {
		t.Errorf("expected time to be '%s' but got '%s'", "3:04AM", value)
	}
}
