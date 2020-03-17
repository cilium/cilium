// Copyright 2012, Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package event provides a reflect-based framework for low-frequency global
dispatching of events, which are values of any arbitrary type, to a set of
listener functions, which are usually registered by plugin packages during init().

Listeners should do work in a separate goroutine if it might block. Dispatch
should be called synchronously to make sure work enters the listener's work
queue before moving on. After Dispatch returns, the listener is responsible for
arranging to flush its work queue before program termination if desired.

For example, any package can define an event type:

	package mypackage

	type MyEvent struct {
		field1, field2 string
	}

Then, any other package (e.g. a plugin) can listen for those events:

	package myplugin

	import (
		"event"
		"mypackage"
	)

	func onMyEvent(ev mypackage.MyEvent) {
		// do something with ev
	}

	func init() {
		event.AddListener(onMyEvent)
	}

Any registered listeners that accept a single argument of type MyEvent will
be called when a value of type MyEvent is dispatched:

	package myotherpackage

	import (
		"event"
		"mypackage"
	)

	func InMediasRes() {
		ev := mypackage.MyEvent{
			field1: "foo",
			field2: "bar",
		}

		event.Dispatch(ev)
	}

In addition, listener functions that accept an interface type will be called
for any dispatched value that implements the specified interface. A listener
that accepts interface{} will be called for every event type. Listeners can also
accept pointer types, but they will only be called if the dispatch site calls
Dispatch() on a pointer.
*/
package event

import (
	"fmt"
	"reflect"
	"sync"
)

var (
	listenersMutex sync.RWMutex // protects listeners and interfaces
	listeners      = make(map[reflect.Type][]interface{})
	interfaces     = make([]reflect.Type, 0)
)

// BadListenerError is raised via panic() when AddListener is called with an
// invalid listener function.
type BadListenerError string

func (why BadListenerError) Error() string {
	return fmt.Sprintf("bad listener func: %s", string(why))
}

// AddListener registers a listener function that will be called when a matching
// event is dispatched. The type of the function's first (and only) argument
// declares the event type (or interface) to listen for.
func AddListener(fn interface{}) {
	listenersMutex.Lock()
	defer listenersMutex.Unlock()

	fnType := reflect.TypeOf(fn)

	// check that the function type is what we think: # of inputs/outputs, etc.
	// panic if conditions not met (because it's a programming error to have that happen)
	switch {
	case fnType.Kind() != reflect.Func:
		panic(BadListenerError("listener must be a function"))
	case fnType.NumIn() != 1:
		panic(BadListenerError("listener must take exactly one input argument"))
	}

	// the first input parameter is the event
	evType := fnType.In(0)

	// keep a list of listeners for each event type
	listeners[evType] = append(listeners[evType], fn)

	// if eventType is an interface, store it in a separate list
	// so we can check non-interface objects against all interfaces
	if evType.Kind() == reflect.Interface {
		interfaces = append(interfaces, evType)
	}
}

// Dispatch sends an event to all registered listeners that were declared
// to accept values of the event's type, or interfaces that the value implements.
func Dispatch(ev interface{}) {
	listenersMutex.RLock()
	defer listenersMutex.RUnlock()

	evType := reflect.TypeOf(ev)
	vals := []reflect.Value{reflect.ValueOf(ev)}

	// call listeners for the actual static type
	callListeners(evType, vals)

	// also check if the type implements any of the registered interfaces
	for _, in := range interfaces {
		if evType.Implements(in) {
			callListeners(in, vals)
		}
	}
}

func callListeners(t reflect.Type, vals []reflect.Value) {
	for _, fn := range listeners[t] {
		reflect.ValueOf(fn).Call(vals)
	}
}

// Updater is an interface that events can implement to combine updating and
// dispatching into one call.
type Updater interface {
	// Update is called by DispatchUpdate() before the event is dispatched.
	Update(update interface{})
}

// DispatchUpdate calls Update() on the event and then dispatches it. This is a
// shortcut for combining updates and dispatches into a single call.
func DispatchUpdate(ev Updater, update interface{}) {
	ev.Update(update)
	Dispatch(ev)
}
