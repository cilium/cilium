package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/connectivity/check"
)

// dummy implements a Scenario.
type dummy struct {
	name string
}

func Dummy(name string) check.Scenario {
	return &dummy{
		name: name,
	}
}

func (s *dummy) Name() string {
	tn := "dummy"
	if s.name == "" {
		return tn
	}
	return fmt.Sprintf("%s:%s", tn, s.name)
}

func (s *dummy) Run(ctx context.Context, t *check.Test) {
	t.NewAction(s, "action-1", nil, nil).Run(func(a *check.Action) {
		a.Log("logging")
		a.Debug("debugging")
		a.Info("informing")
		a.Warn("warning")
	})

	t.NewAction(s, "action-2", nil, nil).Run(func(a *check.Action) {
		a.Log("logging")
		a.Warn("warning")
		a.Fatal("killing :(")
		a.Fail("failing (this should not be printed)")
	})
}
