// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/utils/features"
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

func (s *dummy) Run(_ context.Context, t *check.Test) {
	t.NewAction(s, "action-1", nil, nil, features.IPFamilyAny).Run(func(a *check.Action) {
		a.Log("logging")
		a.Debug("debugging")
		a.Info("informing")
	})

	t.NewAction(s, "action-2", nil, nil, features.IPFamilyAny).Run(func(a *check.Action) {
		a.Log("logging")
		a.Fatal("killing :(")
		a.Fail("failing (this should not be printed)")
	})
}
