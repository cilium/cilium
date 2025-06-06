// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"fmt"
	"os"

	"github.com/cilium/hive/script"
)

// Commands returns the script commands associated with the given client.
func Commands(client Client) map[string]script.Cmd {
	if !client.IsEnabled() {
		return nil
	}

	cmds := cmds{client: client}
	return map[string]script.Cmd{
		"kvstore/update": cmds.update(),
		"kvstore/delete": cmds.delete(),
		"kvstore/list":   cmds.list(),
	}
}

type cmds struct{ client BackendOperations }

func (c cmds) update() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "update kvstore key-value",
			Args:    "key value-file",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, fmt.Errorf("%w: expected key and value file", script.ErrUsage)
			}
			b, err := os.ReadFile(s.Path(args[1]))
			if err != nil {
				return nil, err
			}

			return nil, c.client.Update(s.Context(), args[0], b, false)
		},
	)
}

func (c cmds) delete() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "delete kvstore key-value",
			Args:    "key",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("%w: expected key", script.ErrUsage)
			}
			return nil, c.client.Delete(s.Context(), args[0])
		},
	)
}

func (c cmds) list() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "list kvstore key-value pairs",
			Args:    "(prefix)",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			prefix := ""
			if len(args) > 0 {
				prefix = args[0]
			}
			kvs, err := c.client.ListPrefix(s.Context(), prefix)
			if err != nil {
				return nil, err
			}
			for k, v := range kvs {
				s.Logf("%s: %s\n", k, v.Data)
			}
			return nil, nil
		},
	)
}
