package hivetest

import (
	"bytes"
	"context"
	"log/slog"
	"slices"
	"testing"
)

// Logger returns a logger which forwards structured logs to t.
func Logger(t testing.TB, opts ...LogOption) *slog.Logger {
	th := &testHandler{
		t: t,
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
