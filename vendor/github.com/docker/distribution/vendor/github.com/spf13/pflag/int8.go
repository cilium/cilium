package pflag

import (
	"fmt"
	"strconv"
)

// -- int8 Value
type int8Value int8

func newInt8Value(val int8, p *int8) *int8Value {
	*p = val
	return (*int8Value)(p)
}

func (i *int8Value) Set(s string) error {
	v, err := strconv.ParseInt(s, 0, 8)
	*i = int8Value(v)
	return err
}

func (i *int8Value) Type() string {
	return "int8"
}

func (i *int8Value) String() string { return fmt.Sprintf("%v", *i) }

// Int8Var defines an int8 flag with specified name, default value, and usage string.
// The argument p points to an int8 variable in which to store the value of the flag.
func (f *FlagSet) Int8Var(p *int8, name string, value int8, usage string) {
	f.VarP(newInt8Value(value, p), name, "", usage)
}

// Like Int8Var, but accepts a shorthand letter that can be used after a single dash.
func (f *FlagSet) Int8VarP(p *int8, name, shorthand string, value int8, usage string) {
	f.VarP(newInt8Value(value, p), name, shorthand, usage)
}

// Int8Var defines an int8 flag with specified name, default value, and usage string.
// The argument p points to an int8 variable in which to store the value of the flag.
func Int8Var(p *int8, name string, value int8, usage string) {
	CommandLine.VarP(newInt8Value(value, p), name, "", usage)
}

// Like Int8Var, but accepts a shorthand letter that can be used after a single dash.
func Int8VarP(p *int8, name, shorthand string, value int8, usage string) {
	CommandLine.VarP(newInt8Value(value, p), name, shorthand, usage)
}

// Int8 defines an int8 flag with specified name, default value, and usage string.
// The return value is the address of an int8 variable that stores the value of the flag.
func (f *FlagSet) Int8(name string, value int8, usage string) *int8 {
	p := new(int8)
	f.Int8VarP(p, name, "", value, usage)
	return p
}

// Like Int8, but accepts a shorthand letter that can be used after a single dash.
func (f *FlagSet) Int8P(name, shorthand string, value int8, usage string) *int8 {
	p := new(int8)
	f.Int8VarP(p, name, shorthand, value, usage)
	return p
}

// Int8 defines an int8 flag with specified name, default value, and usage string.
// The return value is the address of an int8 variable that stores the value of the flag.
func Int8(name string, value int8, usage string) *int8 {
	return CommandLine.Int8P(name, "", value, usage)
}

// Like Int8, but accepts a shorthand letter that can be used after a single dash.
func Int8P(name, shorthand string, value int8, usage string) *int8 {
	return CommandLine.Int8P(name, shorthand, value, usage)
}
