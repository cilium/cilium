package hivetest

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sync/atomic"
	"testing"
)

// Logger returns a logger which forwards structured logs to t.
func Logger(t testing.TB, opts ...LogOption) *slog.Logger {
	// We need to make sure that we don't try to log to `t` after the test has
	// completed since that leads to a panic.
	var tDone atomic.Bool
	t.Cleanup(func() {
		tDone.Store(true)
	})

	th := &testHandler{
		tDone: &tDone,
		t:     t,
	}
	for _, o := range opts {
		o(th)
	}
	return slog.New(th)
}

type LogOption func(*testHandler)

func LogLevel(l slog.Level) LogOption {
	return func(th *testHandler) {
		th.level = l
	}
}

// Will be accessed by multiple goroutines - needs to appear immutable.
type testHandler struct {
	t      testing.TB
	tDone  *atomic.Bool
	level  slog.Level
	fields []groupOrAttr
}

type groupOrAttr struct {
	group string
	attrs []slog.Attr
}

func (th *testHandler) Handle(ctx context.Context, r slog.Record) error {
	// This doesn't do the right thing (as we're called from slog), but the API
	// doesn't allow us to skip more callframes.
	th.t.Helper()

	// This is pretty inefficient if the handler has accumulated a lot of
	// context, but necessary to make it trivially thread-safe. If it becomes
	// necessary, we can always cache the handler we create here.
	var buf bytes.Buffer
	var h slog.Handler
	h = slog.NewTextHandler(&buf, &slog.HandlerOptions{
		AddSource: true,
	})
	for _, ga := range th.fields {
		if ga.group != "" {
			h = h.WithGroup(ga.group)
		} else {
			h = h.WithAttrs(ga.attrs)
		}
	}
	if err := h.Handle(ctx, r); err != nil {
		return err
	}

	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "failed to log (likely because the test is no longer running): %v", r)
		}
	}()

	// This is still TOCTOU racy with the call to log below, but we catch the
	// potential panic above.
	if th.tDone.Load() {
		return fmt.Errorf("cannot log to finished test case")
	}
	// Chomp the newline.
	th.t.Log(string(buf.Bytes()[:buf.Len()-1]))

	return nil
}

func (th *testHandler) WithGroup(g string) slog.Handler {
	nt := *th
	nt.fields = append(slices.Clone(th.fields), groupOrAttr{group: g})
	return &nt
}

func (th *testHandler) WithAttrs(as []slog.Attr) slog.Handler {
	nt := *th
	nt.fields = append(slices.Clone(th.fields), groupOrAttr{attrs: as})
	return &nt
}

func (th *testHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return th.level <= l
}
