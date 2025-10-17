package registry

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/cilium/hive/cell"
)

type lifecycle struct {
	hooks []cell.HookInterface
}

func (l *lifecycle) Append(hook cell.HookInterface) {
	l.hooks = append(l.hooks, hook)
}

func (l *lifecycle) Start(_ *slog.Logger, _ context.Context) error {
	for _, hook := range l.hooks {
		if err := hook.Start(nil); err != nil {
			return err
		}
	}
	return nil
}

func (l *lifecycle) Stop(_ *slog.Logger, _ context.Context) error {
	for _, hook := range l.hooks {
		if err := hook.Stop(nil); err != nil {
			return err
		}
	}
	return nil
}

func (l *lifecycle) PrintHooks(_ io.Writer) {
	panic("unimplemented")
}

func TestNewMapSpecRegistry(t *testing.T) {
	lc := &lifecycle{}
	_, err := NewMapSpecRegistry(lc)
	if err != nil {
		t.Fatalf("Failed to create MapSpecRegistry: %v", err)
	}
}
