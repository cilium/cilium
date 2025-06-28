// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"

	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"
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

type cmds struct{ client Client }

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
				return nil, fmt.Errorf("could not read %q: %w", s.Path(args[1]), err)
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
			Args:    "prefix (output file)",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP("output", "o", "plain", "Output format. One of: (plain, json)")
				fs.Bool("keys-only", false, "Only output the listed keys")
				fs.Bool("values-only", false, "Only output the listed values")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			var prefix string
			if len(args) > 0 {
				prefix = args[0]
			}

			keysOnly, _ := s.Flags.GetBool("keys-only")
			valuesOnly, _ := s.Flags.GetBool("values-only")
			if keysOnly && valuesOnly {
				return nil, errors.New("--keys-only and --values-only are mutually exclusive")
			}

			kvs, err := c.client.ListPrefix(s.Context(), prefix)
			if err != nil {
				return nil, fmt.Errorf("error listing %q: %w", prefix, err)
			}

			return func(s *script.State) (stdout string, stderr string, err error) {
				var b bytes.Buffer
				for _, k := range slices.Sorted(maps.Keys(kvs)) {
					if !valuesOnly {
						fmt.Fprintf(&b, "# %s\n", k)
					}

					if !keysOnly {
						outfmt, _ := s.Flags.GetString("output")
						switch outfmt {
						case "plain":
							fmt.Fprintln(&b, string(kvs[k].Data))
						case "json":
							if err := json.Indent(&b, kvs[k].Data, "", "  "); err != nil {
								fmt.Fprintf(&b, "ERROR: %s", err)
							}
							fmt.Fprintln(&b)
						default:
							return "", "", fmt.Errorf("unexpected output format %q", outfmt)
						}
					}

					fmt.Fprint(&b)
				}
				if len(args) == 2 {
					err = os.WriteFile(s.Path(args[1]), b.Bytes(), 0644)
					if err != nil {
						err = fmt.Errorf("could not write %q: %w", s.Path(args[1]), err)
					}
				} else {
					stdout = b.String()
				}
				return
			}, nil
		},
	)
}
