// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/dig"

	"github.com/cilium/hive/internal"
)

type invoker struct {
	funcs []namedFunc
}

type namedFunc struct {
	name string
	fn   any

	infoMu sync.Mutex
	info   *dig.InvokeInfo
}

type InvokerList interface {
	AppendInvoke(func(*slog.Logger, time.Duration) error)
}

func (inv *invoker) invoke(log *slog.Logger, cont container, logThreshold time.Duration) error {
	for i := range inv.funcs {
		nf := &inv.funcs[i]
		log.Debug("Invoking", "function", nf.name)
		t0 := time.Now()

		var opts []dig.InvokeOption
		nf.infoMu.Lock()
		if nf.info == nil {
			nf.info = &dig.InvokeInfo{}
			opts = []dig.InvokeOption{
				dig.FillInvokeInfo(nf.info),
			}
		}
		defer inv.funcs[i].infoMu.Unlock()

		if err := cont.Invoke(nf.fn, opts...); err != nil {
			log.Error("Invoke failed", "error", err, "function", nf.name)
			return err
		}
		d := time.Since(t0)
		if d > logThreshold {
			log.Info("Invoked", "duration", d, "function", nf.name)
		} else {
			log.Debug("Invoked", "duration", d, "function", nf.name)
		}
	}
	return nil
}

func (inv *invoker) Apply(c container) error {
	// Remember the scope in which we need to invoke.
	invoker := func(log *slog.Logger, logThreshold time.Duration) error { return inv.invoke(log, c, logThreshold) }

	// Append the invoker to the list of invoke functions. These are invoked
	// prior to start to build up the objects. They are not invoked directly
	// here as first the configuration flags need to be registered. This allows
	// using hives in a command-line application with many commands and where
	// we don't yet know which command to run, but we still need to register
	// all the flags.
	return c.Invoke(func(l InvokerList) {
		l.AppendInvoke(invoker)
	})
}

func (inv *invoker) Info(container) Info {
	n := NewInfoNode("")
	for i := range inv.funcs {
		namedFunc := &inv.funcs[i]
		namedFunc.infoMu.Lock()
		defer namedFunc.infoMu.Unlock()

		invNode := NewInfoNode(fmt.Sprintf("🛠️ %s", namedFunc.name))
		invNode.condensed = true

		var ins []string
		for _, input := range namedFunc.info.Inputs {
			ins = append(ins, input.String())
		}
		sort.Strings(ins)
		invNode.AddLeaf("⇨ %s", strings.Join(ins, ", "))
		n.Add(invNode)
	}
	return n
}

// Invoke constructs a cell for invoke functions. The invoke functions are executed
// when the hive is started to instantiate all objects via the constructors.
func Invoke(funcs ...any) Cell {
	namedFuncs := []namedFunc{}
	for _, fn := range funcs {
		namedFuncs = append(
			namedFuncs,
			namedFunc{name: internal.FuncNameAndLocation(fn), fn: fn})
	}
	return &invoker{funcs: namedFuncs}
}
