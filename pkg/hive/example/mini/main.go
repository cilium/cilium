// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// A minimal example implementation of dependency injection in Go using reflection.
// For educational purposes only :-)

package main

import (
	"fmt"
	"reflect"
)

type A struct{}

func NewA() *A {
	return &A{}
}

type B struct {
	A *A
}

func NewB(A *A) *B {
	return &B{A}
}

func showB(B *B) {
	fmt.Printf("B: %#v\n", B)
}

func main() {
	c := container{
		providers: make(map[int]provider),
		byType:    make(map[string]int),
		objects:   make(map[string]reflect.Value),
	}

	c.provide(NewA)
	c.provide(NewB)

	c.invoke(showB)
}

type provider struct {
	ctor any
	ins  []reflect.Type
	out  []reflect.Type
}

type container struct {
	nextId    int
	providers map[int]provider
	byType    map[string]int
	objects   map[string]reflect.Value
}

func (c *container) provide(ctor any) {
	typ := reflect.TypeOf(ctor)
	in := make([]reflect.Type, typ.NumIn())
	for i := 0; i < typ.NumIn(); i++ {
		in[i] = typ.In(i)
	}
	out := make([]reflect.Type, typ.NumOut())
	for i := 0; i < typ.NumOut(); i++ {
		o := typ.Out(i)
		out[i] = o
		c.byType[o.String()] = c.nextId
	}
	c.providers[c.nextId] = provider{ctor, in, out}
	c.nextId++
}

func (c *container) construct(name string) reflect.Value {
	fmt.Printf("constructing %q\n", name)

	obj, ok := c.objects[name]
	if ok {
		return obj
	}

	id := c.byType[name]
	provider := c.providers[id]
	ctor := reflect.ValueOf(provider.ctor)
	ctorType := ctor.Type()

	args := make([]reflect.Value, ctorType.NumIn())
	for i := 0; i < ctorType.NumIn(); i++ {
		args[i] = c.construct(ctorType.In(i).String())
	}
	outs := ctor.Call(args)
	for i, out := range outs {
		t := ctorType.Out(i)
		c.objects[t.String()] = out
	}
	return c.objects[name]
}

func (c *container) invoke(fn any) {
	val := reflect.ValueOf(fn)
	typ := val.Type()
	args := make([]reflect.Value, typ.NumIn())
	for i := 0; i < typ.NumIn(); i++ {
		args[i] = c.construct(typ.In(i).String())
	}
	val.Call(args)
}
