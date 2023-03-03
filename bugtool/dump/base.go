// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dump

import "fmt"

// base provides a compositional base for serializable Task types.
// This is the metadata used to identify task types.
//
// Note: Tasks should always use composition for the base, and
// use the mapstructure:",squash" tag so that the task can be correctly
// be decoded.
type base struct {
	Name string `json:"Name",mapstructure:"Name"`
	Kind Kind   `json:"Kind",mapstructure:"Kind"`
}

func (b base) Identifier() string {
	return fmt.Sprintf("%s:%s", b.Kind, b.Name)
}

func (b base) GetName() string {
	return b.Name
}

// Kinds is a list of all valid implementations of Tasks.
var Kinds = []Kind{
	KindDir,
	KindExec,
	KindFile,
	KindRequest,
}

func (b base) validate() error {
	if b.Kind == "" {
		return fmt.Errorf("task kind cannot be empty")
	}
	switch b.Kind {
	case KindDir, KindExec, KindFile, KindRequest:
		return nil
	default:
		return fmt.Errorf("unknown task kind %q (valid kinds: %v)", b.Kind, Kinds)
	}
}
