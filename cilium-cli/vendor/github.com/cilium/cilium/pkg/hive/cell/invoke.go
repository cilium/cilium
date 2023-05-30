// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"time"

	"github.com/cilium/cilium/pkg/hive/internal"
)

type invoker struct {
	cont  container
	funcs []namedFunc
}

type namedFunc struct {
	name string
	fn   any
}

type InvokerList interface {
	AppendInvoke(func() error)
}

func (i *invoker) invoke() error {
	for _, afn := range i.funcs {
		log.WithField("function", afn.name).Debug("Invoking")
		t0 := time.Now()
		if err := i.cont.Invoke(afn.fn); err != nil {
			log.WithError(err).WithField("", afn.name).Error("Invoke failed")
			return err
		}
		d := time.Since(t0)
		log.WithField("duration", d).WithField("function", afn.name).Info("Invoked")
	}
	return nil
}

func (i *invoker) Apply(c container) error {
	// Remember the scope in which we need to invoke.
	i.cont = c

	// Append the invoker to the list of invoke functions. These are invoked
	// prior to start to build up the objects. They are not invoked directly
	// here as first the configuration flags need to be registered. This allows
	// using hives in a command-line application with many commands and where
	// we don't yet know which command to run, but we still need to register
	// all the flags.
	return c.Invoke(func(l InvokerList) {
		l.AppendInvoke(i.invoke)
	})
}

func (i *invoker) Info(container) Info {
	n := NewInfoNode("")
	for _, namedFunc := range i.funcs {
		n.AddLeaf("🛠️ %s: %s", namedFunc.name, internal.PrettyType(namedFunc.fn))
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
