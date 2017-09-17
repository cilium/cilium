// Copyright 2014-2016 The Docker & Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//	Package mflag implements command-line flag parsing.
//
//	Usage:
//
//	Define flags using flag.String(), Bool(), Int(), etc.
//
//	This declares an integer flag, -f or --flagname, stored in the pointer ip, with type *int.
//		import "flag /github.com/docker/libnetwork/client/mflag"
//		var ip = flag.Int([]string{"f", "-flagname"}, 1234, "help message for flagname")
//	If you like, you can bind the flag to a variable using the Var() functions.
//		var flagvar int
//		func init() {
//			// -flaghidden will work, but will be hidden from the usage
//			flag.IntVar(&flagvar, []string{"f", "#flaghidden", "-flagname"}, 1234, "help message for flagname")
//		}
//	Or you can create custom flags that satisfy the Value interface (with
//	pointer receivers) and couple them to flag parsing by
//		flag.Var(&flagVal, []string{"name"}, "help message for flagname")
//	For such flags, the default value is just the initial value of the variable.
//
//	You can also add "deprecated" flags, they are still usable, but are not shown
//	in the usage and will display a warning when you try to use them. `#` before
//	an option means this option is deprecated, if there is an following option
//	without `#` ahead, then that's the replacement, if not, it will just be removed:
//		var ip = flag.Int([]string{"#f", "#flagname", "-flagname"}, 1234, "help message for flagname")
//	this will display: `Warning: '-f' is deprecated, it will be replaced by '--flagname' soon. See usage.` or
//	this will display: `Warning: '-flagname' is deprecated, it will be replaced by '--flagname' soon. See usage.`
//		var ip = flag.Int([]string{"f", "#flagname"}, 1234, "help message for flagname")
//	will display: `Warning: '-flagname' is deprecated, it will be removed soon. See usage.`
//	so you can only use `-f`.
//
//	You can also group one letter flags, bif you declare
//		var v = flag.Bool([]string{"v", "-verbose"}, false, "help message for verbose")
//		var s = flag.Bool([]string{"s", "-slow"}, false, "help message for slow")
//	you will be able to use the -vs or -sv
//
//	After all flags are defined, call
//		flag.Parse()
//	to parse the command line into the defined flags.
//
//	Flags may then be used directly. If you're using the flags themselves,
//	they are all pointers; if you bind to variables, they're values.
//		fmt.Println("ip has value ", *ip)
//		fmt.Println("flagvar has value ", flagvar)
//
//	After parsing, the arguments after the flag are available as the
//	slice flag.Args() or individually as flag.Arg(i).
//	The arguments are indexed from 0 through flag.NArg()-1.
//
//	Command line flag syntax:
//		-flag
//		-flag=x
//		-flag="x"
//		-flag='x'
//		-flag x  // non-boolean flags only
//	One or two minus signs may be used; they are equivalent.
//	The last form is not permitted for boolean flags because the
//	meaning of the command
//		cmd -x *
//	will change if there is a file called 0, false, etc.  You must
//	use the -flag=false form to turn off a boolean flag.
//
//	Flag parsing stops just before the first non-flag argument
//	("-" is a non-flag argument) or after the terminator "--".
//
//	Integer flags accept 1234, 0664, 0x1234 and may be negative.
//	Boolean flags may be 1, 0, t, f, true, false, TRUE, FALSE, True, False.
//	Duration flags accept any input valid for time.ParseDuration.
//
//	The default set of command-line flags is controlled by
//	top-level functions.  The FlagSet type allows one to define
//	independent sets of flags, such as to implement subcommands
//	in a command-line interface. The methods of FlagSet are
//	analogous to the top-level functions for the command-line
//	flag set.

package mflag

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/docker/docker/pkg/homedir"
)

// ErrHelp is the error returned if the flag -help is invoked but no such flag is defined.
var ErrHelp = errors.New("flag: help requested")

// ErrRetry is the error returned if you need to try letter by letter
var ErrRetry = errors.New("flag: retry")

// -- bool Value
type boolValue bool

func newBoolValue(val bool, p *bool) *boolValue {
	*p = val
	return (*boolValue)(p)
}

func (b *boolValue) Set(s string) error {
	v, err := strconv.ParseBool(s)
	*b = boolValue(v)
	return err
}

func (b *boolValue) Get() interface{} { return bool(*b) }

func (b *boolValue) String() string { return fmt.Sprintf("%v", *b) }

func (b *boolValue) IsBoolFlag() bool { return true }

// optional interface to indicate boolean flags that can be
// supplied without "=value" text
type boolFlag interface {
	Value
	IsBoolFlag() bool
}

// -- int Value
type intValue int

func newIntValue(val int, p *int) *intValue {
	*p = val
	return (*intValue)(p)
}

func (i *intValue) Set(s string) error {
	v, err := strconv.ParseInt(s, 0, 64)
	*i = intValue(v)
	return err
}

func (i *intValue) Get() interface{} { return int(*i) }

func (i *intValue) String() string { return fmt.Sprintf("%v", *i) }

// -- int64 Value
type int64Value int64

func newInt64Value(val int64, p *int64) *int64Value {
	*p = val
	return (*int64Value)(p)
}

func (i *int64Value) Set(s string) error {
	v, err := strconv.ParseInt(s, 0, 64)
	*i = int64Value(v)
	return err
}

func (i *int64Value) Get() interface{} { return int64(*i) }

func (i *int64Value) String() string { return fmt.Sprintf("%v", *i) }

// -- uint Value
type uintValue uint

func newUintValue(val uint, p *uint) *uintValue {
	*p = val
	return (*uintValue)(p)
}

func (i *uintValue) Set(s string) error {
	v, err := strconv.ParseUint(s, 0, 64)
	*i = uintValue(v)
	return err
}

func (i *uintValue) Get() interface{} { return uint(*i) }

func (i *uintValue) String() string { return fmt.Sprintf("%v", *i) }

// -- uint64 Value
type uint64Value uint64

func newUint64Value(val uint64, p *uint64) *uint64Value {
	*p = val
	return (*uint64Value)(p)
}

func (i *uint64Value) Set(s string) error {
	v, err := strconv.ParseUint(s, 0, 64)
	*i = uint64Value(v)
	return err
}

func (i *uint64Value) Get() interface{} { return uint64(*i) }

func (i *uint64Value) String() string { return fmt.Sprintf("%v", *i) }

// -- uint16 Value
type uint16Value uint16

func newUint16Value(val uint16, p *uint16) *uint16Value {
	*p = val
	return (*uint16Value)(p)
}

func (i *uint16Value) Set(s string) error {
	v, err := strconv.ParseUint(s, 0, 16)
	*i = uint16Value(v)
	return err
}

func (i *uint16Value) Get() interface{} { return uint16(*i) }

func (i *uint16Value) String() string { return fmt.Sprintf("%v", *i) }

// -- string Value
type stringValue string

func newStringValue(val string, p *string) *stringValue {
	*p = val
	return (*stringValue)(p)
}

func (s *stringValue) Set(val string) error {
	*s = stringValue(val)
	return nil
}

func (s *stringValue) Get() interface{} { return string(*s) }

func (s *stringValue) String() string { return fmt.Sprintf("%s", *s) }

// -- float64 Value
type float64Value float64

func newFloat64Value(val float64, p *float64) *float64Value {
	*p = val
	return (*float64Value)(p)
}

func (f *float64Value) Set(s string) error {
	v, err := strconv.ParseFloat(s, 64)
	*f = float64Value(v)
	return err
}

func (f *float64Value) Get() interface{} { return float64(*f) }

func (f *float64Value) String() string { return fmt.Sprintf("%v", *f) }

// -- time.Duration Value
type durationValue time.Duration

func newDurationValue(val time.Duration, p *time.Duration) *durationValue {
	*p = val
	return (*durationValue)(p)
}

func (d *durationValue) Set(s string) error {
	v, err := time.ParseDuration(s)
	*d = durationValue(v)
	return err
}

func (d *durationValue) Get() interface{} { return time.Duration(*d) }

func (d *durationValue) String() string { return (*time.Duration)(d).String() }

// Value is the interface to the dynamic value stored in a flag.
// (The default value is represented as a string.)
//
// If a Value has an IsBoolFlag() bool method returning true,
// the command-line parser makes -name equivalent to -name=true
// rather than using the next command-line argument.
type Value interface {
	String() string
	Set(string) error
}

// Getter is an interface that allows the contents of a Value to be retrieved.
// It wraps the Value interface, rather than being part of it, because it
// appeared after Go 1 and its compatibility rules. All Value types provided
// by this package satisfy the Getter interface.
type Getter interface {
	Value
	Get() interface{}
}

// ErrorHandling defines how to handle flag parsing errors.
type ErrorHandling int

// ErrorHandling strategies available when a flag parsing error occurs
const (
	ContinueOnError ErrorHandling = iota
	ExitOnError
	PanicOnError
)

// A FlagSet represents a set of defined flags.  The zero value of a FlagSet
// has no name and has ContinueOnError error handling.
type FlagSet struct {
	// Usage is the function called when an error occurs while parsing flags.
	// The field is a function (not a method) that may be changed to point to
	// a custom error handler.
	Usage      func()
	ShortUsage func()

	name             string
	parsed           bool
	actual           map[string]*Flag
	formal           map[string]*Flag
	args             []string // arguments after flags
	errorHandling    ErrorHandling
	output           io.Writer // nil means stderr; use Out() accessor
	nArgRequirements []nArgRequirement
}

// A Flag represents the state of a flag.
type Flag struct {
	Names    []string // name as it appears on command line
	Usage    string   // help message
	Value    Value    // value as set
	DefValue string   // default value (as text); for usage message
}

type flagSlice []string

func (p flagSlice) Len() int { return len(p) }
func (p flagSlice) Less(i, j int) bool {
	pi, pj := strings.TrimPrefix(p[i], "-"), strings.TrimPrefix(p[j], "-")
	lpi, lpj := strings.ToLower(pi), strings.ToLower(pj)
	if lpi != lpj {
		return lpi < lpj
	}
	return pi < pj
}
func (p flagSlice) Swap(i, j int) { p[i], p[j] = p[j], p[i] }

// sortFlags returns the flags as a slice in lexicographical sorted order.
func sortFlags(flags map[string]*Flag) []*Flag {
	var list flagSlice

	// The sorted list is based on the first name, when flag map might use the other names.
	nameMap := make(map[string]string)

	for n, f := range flags {
		fName := strings.TrimPrefix(f.Names[0], "#")
		nameMap[fName] = n
		if len(f.Names) == 1 {
			list = append(list, fName)
			continue
		}

		found := false
		for _, name := range list {
			if name == fName {
				found = true
				break
			}
		}
		if !found {
			list = append(list, fName)
		}
	}
	sort.Sort(list)
	result := make([]*Flag, len(list))
	for i, name := range list {
		result[i] = flags[nameMap[name]]
	}
	return result
}

// Name returns the name of the FlagSet.
func (fs *FlagSet) Name() string {
	return fs.name
}

// Out returns the destination for usage and error messages.
func (fs *FlagSet) Out() io.Writer {
	if fs.output == nil {
		return os.Stderr
	}
	return fs.output
}

// SetOutput sets the destination for usage and error messages.
// If output is nil, os.Stderr is used.
func (fs *FlagSet) SetOutput(output io.Writer) {
	fs.output = output
}

// VisitAll visits the flags in lexicographical order, calling fn for each.
// It visits all flags, even those not set.
func (fs *FlagSet) VisitAll(fn func(*Flag)) {
	for _, flag := range sortFlags(fs.formal) {
		fn(flag)
	}
}

// VisitAll visits the command-line flags in lexicographical order, calling
// fn for each.  It visits all flags, even those not set.
func VisitAll(fn func(*Flag)) {
	CommandLine.VisitAll(fn)
}

// Visit visits the flags in lexicographical order, calling fn for each.
// It visits only those flags that have been set.
func (fs *FlagSet) Visit(fn func(*Flag)) {
	for _, flag := range sortFlags(fs.actual) {
		fn(flag)
	}
}

// Visit visits the command-line flags in lexicographical order, calling fn
// for each.  It visits only those flags that have been set.
func Visit(fn func(*Flag)) {
	CommandLine.Visit(fn)
}

// Lookup returns the Flag structure of the named flag, returning nil if none exists.
func (fs *FlagSet) Lookup(name string) *Flag {
	return fs.formal[name]
}

// IsSet indicates whether the specified flag is set in the given FlagSet
func (fs *FlagSet) IsSet(name string) bool {
	return fs.actual[name] != nil
}

// Lookup returns the Flag structure of the named command-line flag,
// returning nil if none exists.
func Lookup(name string) *Flag {
	return CommandLine.formal[name]
}

// IsSet indicates whether the specified flag was specified at all on the cmd line.
func IsSet(name string) bool {
	return CommandLine.IsSet(name)
}

type nArgRequirementType int

// Indicator used to pass to BadArgs function
const (
	Exact nArgRequirementType = iota
	Max
	Min
)

type nArgRequirement struct {
	Type nArgRequirementType
	N    int
}

// Require adds a requirement about the number of arguments for the FlagSet.
// The first parameter can be Exact, Max, or Min to respectively specify the exact,
// the maximum, or the minimal number of arguments required.
// The actual check is done in FlagSet.CheckArgs().
func (fs *FlagSet) Require(nArgRequirementType nArgRequirementType, nArg int) {
	fs.nArgRequirements = append(fs.nArgRequirements, nArgRequirement{nArgRequirementType, nArg})
}

// CheckArgs uses the requirements set by FlagSet.Require() to validate
// the number of arguments. If the requirements are not met,
// an error message string is returned.
func (fs *FlagSet) CheckArgs() (message string) {
	for _, req := range fs.nArgRequirements {
		var arguments string
		if req.N == 1 {
			arguments = "1 argument"
		} else {
			arguments = fmt.Sprintf("%d arguments", req.N)
		}

		str := func(kind string) string {
			return fmt.Sprintf("%q requires %s%s", fs.name, kind, arguments)
		}

		switch req.Type {
		case Exact:
			if fs.NArg() != req.N {
				return str("")
			}
		case Max:
			if fs.NArg() > req.N {
				return str("a maximum of ")
			}
		case Min:
			if fs.NArg() < req.N {
				return str("a minimum of ")
			}
		}
	}
	return ""
}

// Set sets the value of the named flag.
func (fs *FlagSet) Set(name, value string) error {
	flag, ok := fs.formal[name]
	if !ok {
		return fmt.Errorf("no such flag -%v", name)
	}
	if err := flag.Value.Set(value); err != nil {
		return err
	}
	if fs.actual == nil {
		fs.actual = make(map[string]*Flag)
	}
	fs.actual[name] = flag
	return nil
}

// Set sets the value of the named command-line flag.
func Set(name, value string) error {
	return CommandLine.Set(name, value)
}

// isZeroValue guesses whether the string represents the zero
// value for a flag. It is not accurate but in practice works OK.
func isZeroValue(value string) bool {
	switch value {
	case "false":
		return true
	case "":
		return true
	case "0":
		return true
	}
	return false
}

// PrintDefaults prints, to standard error unless configured
// otherwise, the default values of all defined flags in the set.
func (fs *FlagSet) PrintDefaults() {
	writer := tabwriter.NewWriter(fs.Out(), 20, 1, 3, ' ', 0)
	home := homedir.Get()

	// Don't substitute when HOME is /
	if runtime.GOOS != "windows" && home == "/" {
		home = ""
	}

	// Add a blank line between cmd description and list of options
	if fs.FlagCount() > 0 {
		fmt.Fprintln(writer, "")
	}

	fs.VisitAll(func(flag *Flag) {
		names := []string{}
		for _, name := range flag.Names {
			if name[0] != '#' {
				names = append(names, name)
			}
		}
		if len(names) > 0 && len(flag.Usage) > 0 {
			val := flag.DefValue

			if home != "" && strings.HasPrefix(val, home) {
				val = homedir.GetShortcutString() + val[len(home):]
			}

			if isZeroValue(val) {
				format := "  -%s"
				fmt.Fprintf(writer, format, strings.Join(names, ", -"))
			} else {
				format := "  -%s=%s"
				fmt.Fprintf(writer, format, strings.Join(names, ", -"), val)
			}
			for _, line := range strings.Split(flag.Usage, "\n") {
				fmt.Fprintln(writer, "\t", line)
			}
		}
	})
	writer.Flush()
}

// PrintDefaults prints to standard error the default values of all defined command-line flags.
func PrintDefaults() {
	CommandLine.PrintDefaults()
}

// defaultUsage is the default function to print a usage message.
func defaultUsage(fs *FlagSet) {
	if fs.name == "" {
		fmt.Fprintf(fs.Out(), "Usage:\n")
	} else {
		fmt.Fprintf(fs.Out(), "Usage of %s:\n", fs.name)
	}
	fs.PrintDefaults()
}

// NOTE: Usage is not just defaultUsage(CommandLine)
// because it serves (via godoc flag Usage) as the example
// for how to write your own usage function.

// Usage prints to standard error a usage message documenting all defined command-line flags.
// The function is a variable that may be changed to point to a custom function.
var Usage = func() {
	fmt.Fprintf(CommandLine.Out(), "Usage of %s:\n", os.Args[0])
	PrintDefaults()
}

// ShortUsage prints to standard error a usage message documenting the standard command layout
// The function is a variable that may be changed to point to a custom function.
var ShortUsage = func() {
	fmt.Fprintf(CommandLine.output, "Usage of %s:\n", os.Args[0])
}

// FlagCount returns the number of flags that have been defined.
func (fs *FlagSet) FlagCount() int { return len(sortFlags(fs.formal)) }

// FlagCountUndeprecated returns the number of undeprecated flags that have been defined.
func (fs *FlagSet) FlagCountUndeprecated() int {
	count := 0
	for _, flag := range sortFlags(fs.formal) {
		for _, name := range flag.Names {
			if name[0] != '#' {
				count++
				break
			}
		}
	}
	return count
}

// NFlag returns the number of flags that have been set.
func (fs *FlagSet) NFlag() int { return len(fs.actual) }

// NFlag returns the number of command-line flags that have been set.
func NFlag() int { return len(CommandLine.actual) }

// Arg returns the i'th argument.  Arg(0) is the first remaining argument
// after flags have been processed.
func (fs *FlagSet) Arg(i int) string {
	if i < 0 || i >= len(fs.args) {
		return ""
	}
	return fs.args[i]
}

// Arg returns the i'th command-line argument.  Arg(0) is the first remaining argument
// after flags have been processed.
func Arg(i int) string {
	return CommandLine.Arg(i)
}

// NArg is the number of arguments remaining after flags have been processed.
func (fs *FlagSet) NArg() int { return len(fs.args) }

// NArg is the number of arguments remaining after flags have been processed.
func NArg() int { return len(CommandLine.args) }

// Args returns the non-flag arguments.
func (fs *FlagSet) Args() []string { return fs.args }

// Args returns the non-flag command-line arguments.
func Args() []string { return CommandLine.args }

// BoolVar defines a bool flag with specified name, default value, and usage string.
// The argument p points to a bool variable in which to store the value of the flag.
func (fs *FlagSet) BoolVar(p *bool, names []string, value bool, usage string) {
	fs.Var(newBoolValue(value, p), names, usage)
}

// BoolVar defines a bool flag with specified name, default value, and usage string.
// The argument p points to a bool variable in which to store the value of the flag.
func BoolVar(p *bool, names []string, value bool, usage string) {
	CommandLine.Var(newBoolValue(value, p), names, usage)
}

// Bool defines a bool flag with specified name, default value, and usage string.
// The return value is the address of a bool variable that stores the value of the flag.
func (fs *FlagSet) Bool(names []string, value bool, usage string) *bool {
	p := new(bool)
	fs.BoolVar(p, names, value, usage)
	return p
}

// Bool defines a bool flag with specified name, default value, and usage string.
// The return value is the address of a bool variable that stores the value of the flag.
func Bool(names []string, value bool, usage string) *bool {
	return CommandLine.Bool(names, value, usage)
}

// IntVar defines an int flag with specified name, default value, and usage string.
// The argument p points to an int variable in which to store the value of the flag.
func (fs *FlagSet) IntVar(p *int, names []string, value int, usage string) {
	fs.Var(newIntValue(value, p), names, usage)
}

// IntVar defines an int flag with specified name, default value, and usage string.
// The argument p points to an int variable in which to store the value of the flag.
func IntVar(p *int, names []string, value int, usage string) {
	CommandLine.Var(newIntValue(value, p), names, usage)
}

// Int defines an int flag with specified name, default value, and usage string.
// The return value is the address of an int variable that stores the value of the flag.
func (fs *FlagSet) Int(names []string, value int, usage string) *int {
	p := new(int)
	fs.IntVar(p, names, value, usage)
	return p
}

// Int defines an int flag with specified name, default value, and usage string.
// The return value is the address of an int variable that stores the value of the flag.
func Int(names []string, value int, usage string) *int {
	return CommandLine.Int(names, value, usage)
}

// Int64Var defines an int64 flag with specified name, default value, and usage string.
// The argument p points to an int64 variable in which to store the value of the flag.
func (fs *FlagSet) Int64Var(p *int64, names []string, value int64, usage string) {
	fs.Var(newInt64Value(value, p), names, usage)
}

// Int64Var defines an int64 flag with specified name, default value, and usage string.
// The argument p points to an int64 variable in which to store the value of the flag.
func Int64Var(p *int64, names []string, value int64, usage string) {
	CommandLine.Var(newInt64Value(value, p), names, usage)
}

// Int64 defines an int64 flag with specified name, default value, and usage string.
// The return value is the address of an int64 variable that stores the value of the flag.
func (fs *FlagSet) Int64(names []string, value int64, usage string) *int64 {
	p := new(int64)
	fs.Int64Var(p, names, value, usage)
	return p
}

// Int64 defines an int64 flag with specified name, default value, and usage string.
// The return value is the address of an int64 variable that stores the value of the flag.
func Int64(names []string, value int64, usage string) *int64 {
	return CommandLine.Int64(names, value, usage)
}

// UintVar defines a uint flag with specified name, default value, and usage string.
// The argument p points to a uint variable in which to store the value of the flag.
func (fs *FlagSet) UintVar(p *uint, names []string, value uint, usage string) {
	fs.Var(newUintValue(value, p), names, usage)
}

// UintVar defines a uint flag with specified name, default value, and usage string.
// The argument p points to a uint  variable in which to store the value of the flag.
func UintVar(p *uint, names []string, value uint, usage string) {
	CommandLine.Var(newUintValue(value, p), names, usage)
}

// Uint defines a uint flag with specified name, default value, and usage string.
// The return value is the address of a uint  variable that stores the value of the flag.
func (fs *FlagSet) Uint(names []string, value uint, usage string) *uint {
	p := new(uint)
	fs.UintVar(p, names, value, usage)
	return p
}

// Uint defines a uint flag with specified name, default value, and usage string.
// The return value is the address of a uint  variable that stores the value of the flag.
func Uint(names []string, value uint, usage string) *uint {
	return CommandLine.Uint(names, value, usage)
}

// Uint64Var defines a uint64 flag with specified name, default value, and usage string.
// The argument p points to a uint64 variable in which to store the value of the flag.
func (fs *FlagSet) Uint64Var(p *uint64, names []string, value uint64, usage string) {
	fs.Var(newUint64Value(value, p), names, usage)
}

// Uint64Var defines a uint64 flag with specified name, default value, and usage string.
// The argument p points to a uint64 variable in which to store the value of the flag.
func Uint64Var(p *uint64, names []string, value uint64, usage string) {
	CommandLine.Var(newUint64Value(value, p), names, usage)
}

// Uint64 defines a uint64 flag with specified name, default value, and usage string.
// The return value is the address of a uint64 variable that stores the value of the flag.
func (fs *FlagSet) Uint64(names []string, value uint64, usage string) *uint64 {
	p := new(uint64)
	fs.Uint64Var(p, names, value, usage)
	return p
}

// Uint64 defines a uint64 flag with specified name, default value, and usage string.
// The return value is the address of a uint64 variable that stores the value of the flag.
func Uint64(names []string, value uint64, usage string) *uint64 {
	return CommandLine.Uint64(names, value, usage)
}

// Uint16Var defines a uint16 flag with specified name, default value, and usage string.
// The argument p points to a uint16 variable in which to store the value of the flag.
func (fs *FlagSet) Uint16Var(p *uint16, names []string, value uint16, usage string) {
	fs.Var(newUint16Value(value, p), names, usage)
}

// Uint16Var defines a uint16 flag with specified name, default value, and usage string.
// The argument p points to a uint16 variable in which to store the value of the flag.
func Uint16Var(p *uint16, names []string, value uint16, usage string) {
	CommandLine.Var(newUint16Value(value, p), names, usage)
}

// Uint16 defines a uint16 flag with specified name, default value, and usage string.
// The return value is the address of a uint16 variable that stores the value of the flag.
func (fs *FlagSet) Uint16(names []string, value uint16, usage string) *uint16 {
	p := new(uint16)
	fs.Uint16Var(p, names, value, usage)
	return p
}

// Uint16 defines a uint16 flag with specified name, default value, and usage string.
// The return value is the address of a uint16 variable that stores the value of the flag.
func Uint16(names []string, value uint16, usage string) *uint16 {
	return CommandLine.Uint16(names, value, usage)
}

// StringVar defines a string flag with specified name, default value, and usage string.
// The argument p points to a string variable in which to store the value of the flag.
func (fs *FlagSet) StringVar(p *string, names []string, value string, usage string) {
	fs.Var(newStringValue(value, p), names, usage)
}

// StringVar defines a string flag with specified name, default value, and usage string.
// The argument p points to a string variable in which to store the value of the flag.
func StringVar(p *string, names []string, value string, usage string) {
	CommandLine.Var(newStringValue(value, p), names, usage)
}

// String defines a string flag with specified name, default value, and usage string.
// The return value is the address of a string variable that stores the value of the flag.
func (fs *FlagSet) String(names []string, value string, usage string) *string {
	p := new(string)
	fs.StringVar(p, names, value, usage)
	return p
}

// String defines a string flag with specified name, default value, and usage string.
// The return value is the address of a string variable that stores the value of the flag.
func String(names []string, value string, usage string) *string {
	return CommandLine.String(names, value, usage)
}

// Float64Var defines a float64 flag with specified name, default value, and usage string.
// The argument p points to a float64 variable in which to store the value of the flag.
func (fs *FlagSet) Float64Var(p *float64, names []string, value float64, usage string) {
	fs.Var(newFloat64Value(value, p), names, usage)
}

// Float64Var defines a float64 flag with specified name, default value, and usage string.
// The argument p points to a float64 variable in which to store the value of the flag.
func Float64Var(p *float64, names []string, value float64, usage string) {
	CommandLine.Var(newFloat64Value(value, p), names, usage)
}

// Float64 defines a float64 flag with specified name, default value, and usage string.
// The return value is the address of a float64 variable that stores the value of the flag.
func (fs *FlagSet) Float64(names []string, value float64, usage string) *float64 {
	p := new(float64)
	fs.Float64Var(p, names, value, usage)
	return p
}

// Float64 defines a float64 flag with specified name, default value, and usage string.
// The return value is the address of a float64 variable that stores the value of the flag.
func Float64(names []string, value float64, usage string) *float64 {
	return CommandLine.Float64(names, value, usage)
}

// DurationVar defines a time.Duration flag with specified name, default value, and usage string.
// The argument p points to a time.Duration variable in which to store the value of the flag.
func (fs *FlagSet) DurationVar(p *time.Duration, names []string, value time.Duration, usage string) {
	fs.Var(newDurationValue(value, p), names, usage)
}

// DurationVar defines a time.Duration flag with specified name, default value, and usage string.
// The argument p points to a time.Duration variable in which to store the value of the flag.
func DurationVar(p *time.Duration, names []string, value time.Duration, usage string) {
	CommandLine.Var(newDurationValue(value, p), names, usage)
}

// Duration defines a time.Duration flag with specified name, default value, and usage string.
// The return value is the address of a time.Duration variable that stores the value of the flag.
func (fs *FlagSet) Duration(names []string, value time.Duration, usage string) *time.Duration {
	p := new(time.Duration)
	fs.DurationVar(p, names, value, usage)
	return p
}

// Duration defines a time.Duration flag with specified name, default value, and usage string.
// The return value is the address of a time.Duration variable that stores the value of the flag.
func Duration(names []string, value time.Duration, usage string) *time.Duration {
	return CommandLine.Duration(names, value, usage)
}

// Var defines a flag with the specified name and usage string. The type and
// value of the flag are represented by the first argument, of type Value, which
// typically holds a user-defined implementation of Value. For instance, the
// caller could create a flag that turns a comma-separated string into a slice
// of strings by giving the slice the methods of Value; in particular, Set would
// decompose the comma-separated string into the slice.
func (fs *FlagSet) Var(value Value, names []string, usage string) {
	// Remember the default value as a string; it won't change.
	flag := &Flag{names, usage, value, value.String()}
	for _, name := range names {
		name = strings.TrimPrefix(name, "#")
		_, alreadythere := fs.formal[name]
		if alreadythere {
			var msg string
			if fs.name == "" {
				msg = fmt.Sprintf("flag redefined: %s", name)
			} else {
				msg = fmt.Sprintf("%s flag redefined: %s", fs.name, name)
			}
			fmt.Fprintln(fs.Out(), msg)
			panic(msg) // Happens only if flags are declared with identical names
		}
		if fs.formal == nil {
			fs.formal = make(map[string]*Flag)
		}
		fs.formal[name] = flag
	}
}

// Var defines a flag with the specified name and usage string. The type and
// value of the flag are represented by the first argument, of type Value, which
// typically holds a user-defined implementation of Value. For instance, the
// caller could create a flag that turns a comma-separated string into a slice
// of strings by giving the slice the methods of Value; in particular, Set would
// decompose the comma-separated string into the slice.
func Var(value Value, names []string, usage string) {
	CommandLine.Var(value, names, usage)
}

// failf prints to standard error a formatted error and usage message and
// returns the error.
func (fs *FlagSet) failf(format string, a ...interface{}) error {
	err := fmt.Errorf(format, a...)
	fmt.Fprintln(fs.Out(), err)
	if os.Args[0] == fs.name {
		fmt.Fprintf(fs.Out(), "See '%s --help'.\n", os.Args[0])
	} else {
		fmt.Fprintf(fs.Out(), "See '%s %s --help'.\n", os.Args[0], fs.name)
	}
	return err
}

// usage calls the Usage method for the flag set, or the usage function if
// the flag set is CommandLine.
func (fs *FlagSet) usage() {
	if fs == CommandLine {
		Usage()
	} else if fs.Usage == nil {
		defaultUsage(fs)
	} else {
		fs.Usage()
	}
}

func trimQuotes(str string) string {
	if len(str) == 0 {
		return str
	}
	type quote struct {
		start, end byte
	}

	// All valid quote types.
	quotes := []quote{
		// Double quotes
		{
			start: '"',
			end:   '"',
		},

		// Single quotes
		{
			start: '\'',
			end:   '\'',
		},
	}

	for _, quote := range quotes {
		// Only strip if outermost match.
		if str[0] == quote.start && str[len(str)-1] == quote.end {
			str = str[1 : len(str)-1]
			break
		}
	}

	return str
}

// parseOne parses one flag. It reports whether a flag was seen.
func (fs *FlagSet) parseOne() (bool, string, error) {
	if len(fs.args) == 0 {
		return false, "", nil
	}
	s := fs.args[0]
	if len(s) == 0 || s[0] != '-' || len(s) == 1 {
		return false, "", nil
	}
	if s[1] == '-' && len(s) == 2 { // "--" terminates the flags
		fs.args = fs.args[1:]
		return false, "", nil
	}
	name := s[1:]
	if len(name) == 0 || name[0] == '=' {
		return false, "", fs.failf("bad flag syntax: %s", s)
	}

	// it's a flag. does it have an argument?
	fs.args = fs.args[1:]
	hasValue := false
	value := ""
	if i := strings.Index(name, "="); i != -1 {
		value = trimQuotes(name[i+1:])
		hasValue = true
		name = name[:i]
	}

	m := fs.formal
	flag, alreadythere := m[name] // BUG
	if !alreadythere {
		if name == "-help" || name == "help" || name == "h" { // special case for nice help message.
			fs.usage()
			return false, "", ErrHelp
		}
		if len(name) > 0 && name[0] == '-' {
			return false, "", fs.failf("flag provided but not defined: -%s", name)
		}
		return false, name, ErrRetry
	}
	if fv, ok := flag.Value.(boolFlag); ok && fv.IsBoolFlag() { // special case: doesn't need an arg
		if hasValue {
			if err := fv.Set(value); err != nil {
				return false, "", fs.failf("invalid boolean value %q for  -%s: %v", value, name, err)
			}
		} else {
			fv.Set("true")
		}
	} else {
		// It must have a value, which might be the next argument.
		if !hasValue && len(fs.args) > 0 {
			// value is the next arg
			hasValue = true
			value, fs.args = fs.args[0], fs.args[1:]
		}
		if !hasValue {
			return false, "", fs.failf("flag needs an argument: -%s", name)
		}
		if err := flag.Value.Set(value); err != nil {
			return false, "", fs.failf("invalid value %q for flag -%s: %v", value, name, err)
		}
	}
	if fs.actual == nil {
		fs.actual = make(map[string]*Flag)
	}
	fs.actual[name] = flag
	for i, n := range flag.Names {
		if n == fmt.Sprintf("#%s", name) {
			replacement := ""
			for j := i; j < len(flag.Names); j++ {
				if flag.Names[j][0] != '#' {
					replacement = flag.Names[j]
					break
				}
			}
			if replacement != "" {
				fmt.Fprintf(fs.Out(), "Warning: '-%s' is deprecated, it will be replaced by '-%s' soon. See usage.\n", name, replacement)
			} else {
				fmt.Fprintf(fs.Out(), "Warning: '-%s' is deprecated, it will be removed soon. See usage.\n", name)
			}
		}
	}
	return true, "", nil
}

// Parse parses flag definitions from the argument list, which should not
// include the command name.  Must be called after all flags in the FlagSet
// are defined and before flags are accessed by the program.
// The return value will be ErrHelp if -help was set but not defined.
func (fs *FlagSet) Parse(arguments []string) error {
	fs.parsed = true
	fs.args = arguments
	for {
		seen, name, err := fs.parseOne()
		if seen {
			continue
		}
		if err == nil {
			break
		}
		if err == ErrRetry {
			if len(name) > 1 {
				err = nil
				for _, letter := range strings.Split(name, "") {
					fs.args = append([]string{"-" + letter}, fs.args...)
					seen2, _, err2 := fs.parseOne()
					if seen2 {
						continue
					}
					if err2 != nil {
						err = fs.failf("flag provided but not defined: -%s", name)
						break
					}
				}
				if err == nil {
					continue
				}
			} else {
				err = fs.failf("flag provided but not defined: -%s", name)
			}
		}
		switch fs.errorHandling {
		case ContinueOnError:
			return err
		case ExitOnError:
			os.Exit(125)
		case PanicOnError:
			panic(err)
		}
	}
	return nil
}

// ParseFlags is a utility function that adds a help flag if withHelp is true,
// calls fs.Parse(args) and prints a relevant error message if there are
// incorrect number of arguments. It returns error only if error handling is
// set to ContinueOnError and parsing fails. If error handling is set to
// ExitOnError, it's safe to ignore the return value.
func (fs *FlagSet) ParseFlags(args []string, withHelp bool) error {
	var help *bool
	if withHelp {
		help = fs.Bool([]string{"#help", "-help"}, false, "Print usage")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if help != nil && *help {
		fs.SetOutput(os.Stdout)
		fs.Usage()
		os.Exit(0)
	}
	if str := fs.CheckArgs(); str != "" {
		fs.SetOutput(os.Stderr)
		fs.ReportError(str, withHelp)
		fs.ShortUsage()
		os.Exit(1)
	}
	return nil
}

// ReportError is a utility method that prints a user-friendly message
// containing the error that occurred during parsing and a suggestion to get help
func (fs *FlagSet) ReportError(str string, withHelp bool) {
	if withHelp {
		if os.Args[0] == fs.Name() {
			str += ".\nSee '" + os.Args[0] + " --help'"
		} else {
			str += ".\nSee '" + os.Args[0] + " " + fs.Name() + " --help'"
		}
	}
	fmt.Fprintf(fs.Out(), "%s: %s.\n", os.Args[0], str)
}

// Parsed reports whether fs.Parse has been called.
func (fs *FlagSet) Parsed() bool {
	return fs.parsed
}

// Parse parses the command-line flags from os.Args[1:].  Must be called
// after all flags are defined and before flags are accessed by the program.
func Parse() {
	// Ignore errors; CommandLine is set for ExitOnError.
	CommandLine.Parse(os.Args[1:])
}

// Parsed returns true if the command-line flags have been parsed.
func Parsed() bool {
	return CommandLine.Parsed()
}

// CommandLine is the default set of command-line flags, parsed from os.Args.
// The top-level functions such as BoolVar, Arg, and on are wrappers for the
// methods of CommandLine.
var CommandLine = NewFlagSet(os.Args[0], ExitOnError)

// NewFlagSet returns a new, empty flag set with the specified name and
// error handling property.
func NewFlagSet(name string, errorHandling ErrorHandling) *FlagSet {
	f := &FlagSet{
		name:          name,
		errorHandling: errorHandling,
	}
	return f
}

// Init sets the name and error handling property for a flag set.
// By default, the zero FlagSet uses an empty name and the
// ContinueOnError error handling policy.
func (fs *FlagSet) Init(name string, errorHandling ErrorHandling) {
	fs.name = name
	fs.errorHandling = errorHandling
}

type mergeVal struct {
	Value
	key  string
	fset *FlagSet
}

func (v mergeVal) Set(s string) error {
	return v.fset.Set(v.key, s)
}

func (v mergeVal) IsBoolFlag() bool {
	if b, ok := v.Value.(boolFlag); ok {
		return b.IsBoolFlag()
	}
	return false
}

// Name returns the name of a mergeVal.
// If the original value had a name, return the original name,
// otherwise, return the key asinged to this mergeVal.
func (v mergeVal) Name() string {
	type namedValue interface {
		Name() string
	}
	if nVal, ok := v.Value.(namedValue); ok {
		return nVal.Name()
	}
	return v.key
}

// Merge is an helper function that merges n FlagSets into a single dest FlagSet
// In case of name collision between the flagsets it will apply
// the destination FlagSet's errorHandling behavior.
func Merge(dest *FlagSet, flagsets ...*FlagSet) error {
	for _, fset := range flagsets {
		if fset.formal == nil {
			continue
		}
		for k, f := range fset.formal {
			if _, ok := dest.formal[k]; ok {
				var err error
				if fset.name == "" {
					err = fmt.Errorf("flag redefined: %s", k)
				} else {
					err = fmt.Errorf("%s flag redefined: %s", fset.name, k)
				}
				fmt.Fprintln(fset.Out(), err.Error())
				// Happens only if flags are declared with identical names
				switch dest.errorHandling {
				case ContinueOnError:
					return err
				case ExitOnError:
					os.Exit(2)
				case PanicOnError:
					panic(err)
				}
			}
			newF := *f
			newF.Value = mergeVal{f.Value, k, fset}
			if dest.formal == nil {
				dest.formal = make(map[string]*Flag)
			}
			dest.formal[k] = &newF
		}
	}
	return nil
}

// IsEmpty reports if the FlagSet is actually empty.
func (fs *FlagSet) IsEmpty() bool {
	return len(fs.actual) == 0
}
