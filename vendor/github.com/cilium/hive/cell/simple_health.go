// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/cilium/hive/script"
)

type simpleHealthRoot struct {
	sync.Mutex
	all map[string]*SimpleHealth
}

type SimpleHealth struct {
	*simpleHealthRoot

	Scope  string
	Level  Level
	Status string
	Error  error
}

// NewScope implements cell.Health.
func (h *SimpleHealth) NewScope(name string) Health {
	h.Lock()
	defer h.Unlock()

	h2 := &SimpleHealth{
		simpleHealthRoot: h.simpleHealthRoot,
		Scope:            h.Scope + "." + name,
	}
	h.all[name] = h2
	return h2
}

func (h *SimpleHealth) GetChild(fullName string) *SimpleHealth {
	h.Lock()
	defer h.Unlock()

	if child, ok := h.all[fullName]; ok {
		return child
	}
	return nil
}

// Degraded implements cell.Health.
func (h *SimpleHealth) Degraded(reason string, err error) {
	h.Lock()
	defer h.Unlock()

	h.Level = StatusDegraded
	h.Status = reason
	h.Error = err
}

// OK implements cell.Health.
func (h *SimpleHealth) OK(status string) {
	h.Lock()
	defer h.Unlock()

	h.Level = StatusOK
	h.Status = status
	h.Error = nil
}

// Stopped implements cell.Health.
func (h *SimpleHealth) Stopped(reason string) {
	h.Lock()
	defer h.Unlock()

	h.Level = StatusStopped
	h.Status = reason
	h.Error = nil
}

func (h *SimpleHealth) Close() {
	h.Lock()
	defer h.Unlock()

	delete(h.all, h.Scope)
}

func NewSimpleHealth() (Health, *SimpleHealth) {
	h := &SimpleHealth{
		simpleHealthRoot: &simpleHealthRoot{
			all: make(map[string]*SimpleHealth),
		},
	}
	return h, h
}

// SimpleHealthCmd for showing or checking the simple module health state.
// Not provided as hive.ScriptCmdOut due to cyclic import issues. To include
// provide with: hive.ScriptCmdOut("health", SimpleHealthCmd(simpleHealth)))
//
// Example:
//
//	# show health
//	health
//
//	# grep health
//	health 'my-module: level=OK'
func SimpleHealthCmd(h *SimpleHealth) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Show or grep simple health",
			Args:    "(pattern)",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			var re *regexp.Regexp
			if len(args) == 1 {
				re = regexp.MustCompile(args[0])
			}
			for s.Context().Err() == nil {
				h.Lock()
				for name, h := range h.all {
					var errStr string
					if h.Error != nil {
						errStr = h.Error.Error()
					}
					line := fmt.Sprintf("%s: level=%s message=%s error=%s", name, h.Level, h.Status, errStr)
					if re != nil {
						if re.Match([]byte(line)) {
							h.Unlock()
							s.Logf("matched: %s\n", line)
							return nil, nil
						}
					} else {
						fmt.Fprintln(s.LogWriter(), line)
					}
				}
				h.Unlock()
				if re == nil {
					return nil, nil
				}
				time.Sleep(10 * time.Millisecond)
			}
			return nil, fmt.Errorf("no match for %s", re)
		},
	)
}

var _ Health = &SimpleHealth{}

var SimpleHealthCell = Provide(NewSimpleHealth)
