package cli

import (
	"errors"
	"flag"
	"strconv"
	"strings"
	"time"
)

// Context is a type that is passed through to
// each Handler action in a cli application. Context
// can be used to retrieve context-specific Args and
// parsed command-line options.
type Context struct {
	App            *App
	Command        Command
	flagSet        *flag.FlagSet
	setFlags       map[string]bool
	globalSetFlags map[string]bool
	parentContext  *Context
}

// Creates a new context. For use in when invoking an App or Command action.
func NewContext(app *App, set *flag.FlagSet, parentCtx *Context) *Context {
	return &Context{App: app, flagSet: set, parentContext: parentCtx}
}

// Looks up the value of a local int flag, returns 0 if no int flag exists
func (c *Context) Int(name string) int {
	return lookupInt(name, c.flagSet)
}

// Looks up the value of a local time.Duration flag, returns 0 if no time.Duration flag exists
func (c *Context) Duration(name string) time.Duration {
	return lookupDuration(name, c.flagSet)
}

// Looks up the value of a local float64 flag, returns 0 if no float64 flag exists
func (c *Context) Float64(name string) float64 {
	return lookupFloat64(name, c.flagSet)
}

// Looks up the value of a local bool flag, returns false if no bool flag exists
func (c *Context) Bool(name string) bool {
	return lookupBool(name, c.flagSet)
}

// Looks up the value of a local boolT flag, returns false if no bool flag exists
func (c *Context) BoolT(name string) bool {
	return lookupBoolT(name, c.flagSet)
}

// Looks up the value of a local string flag, returns "" if no string flag exists
func (c *Context) String(name string) string {
	return lookupString(name, c.flagSet)
}

// Looks up the value of a local string slice flag, returns nil if no string slice flag exists
func (c *Context) StringSlice(name string) []string {
	return lookupStringSlice(name, c.flagSet)
}

// Looks up the value of a local int slice flag, returns nil if no int slice flag exists
func (c *Context) IntSlice(name string) []int {
	return lookupIntSlice(name, c.flagSet)
}

// Looks up the value of a local generic flag, returns nil if no generic flag exists
func (c *Context) Generic(name string) interface{} {
	return lookupGeneric(name, c.flagSet)
}

// Looks up the value of a global int flag, returns 0 if no int flag exists
func (c *Context) GlobalInt(name string) int {
	if fs := lookupGlobalFlagSet(name, c); fs != nil {
		return lookupInt(name, fs)
	}
	return 0
}

// Looks up the value of a global time.Duration flag, returns 0 if no time.Duration flag exists
func (c *Context) GlobalDuration(name string) time.Duration {
	if fs := lookupGlobalFlagSet(name, c); fs != nil {
		return lookupDuration(name, fs)
	}
	return 0
}

// Looks up the value of a global bool flag, returns false if no bool flag exists
func (c *Context) GlobalBool(name string) bool {
	if fs := lookupGlobalFlagSet(name, c); fs != nil {
		return lookupBool(name, fs)
	}
	return false
}

// Looks up the value of a global string flag, returns "" if no string flag exists
func (c *Context) GlobalString(name string) string {
	if fs := lookupGlobalFlagSet(name, c); fs != nil {
		return lookupString(name, fs)
	}
	return ""
}

// Looks up the value of a global string slice flag, returns nil if no string slice flag exists
func (c *Context) GlobalStringSlice(name string) []string {
	if fs := lookupGlobalFlagSet(name, c); fs != nil {
		return lookupStringSlice(name, fs)
	}
	return nil
}

// Looks up the value of a global int slice flag, returns nil if no int slice flag exists
func (c *Context) GlobalIntSlice(name string) []int {
	if fs := lookupGlobalFlagSet(name, c); fs != nil {
		return lookupIntSlice(name, fs)
	}
	return nil
}

// Looks up the value of a global generic flag, returns nil if no generic flag exists
func (c *Context) GlobalGeneric(name string) interface{} {
	if fs := lookupGlobalFlagSet(name, c); fs != nil {
		return lookupGeneric(name, fs)
	}
	return nil
}

// Returns the number of flags set
func (c *Context) NumFlags() int {
	return c.flagSet.NFlag()
}

// Determines if the flag was actually set
func (c *Context) IsSet(name string) bool {
	if c.setFlags == nil {
		c.setFlags = make(map[string]bool)
		c.flagSet.Visit(func(f *flag.Flag) {
			c.setFlags[f.Name] = true
		})
	}
	return c.setFlags[name] == true
}

// Determines if the global flag was actually set
func (c *Context) GlobalIsSet(name string) bool {
	if c.globalSetFlags == nil {
		c.globalSetFlags = make(map[string]bool)
		ctx := c
		if ctx.parentContext != nil {
			ctx = ctx.parentContext
		}
		for ; ctx != nil && c.globalSetFlags[name] == false; ctx = ctx.parentContext {
			ctx.flagSet.Visit(func(f *flag.Flag) {
				c.globalSetFlags[f.Name] = true
			})
		}
	}
	return c.globalSetFlags[name]
}

// Returns a slice of flag names used in this context.
func (c *Context) FlagNames() (names []string) {
	for _, flag := range c.Command.Flags {
		name := strings.Split(flag.getName(), ",")[0]
		if name == "help" {
			continue
		}
		names = append(names, name)
	}
	return
}

// Returns a slice of global flag names used by the app.
func (c *Context) GlobalFlagNames() (names []string) {
	for _, flag := range c.App.Flags {
		name := strings.Split(flag.getName(), ",")[0]
		if name == "help" || name == "version" {
			continue
		}
		names = append(names, name)
	}
	return
}

// Returns the parent context, if any
func (c *Context) Parent() *Context {
	return c.parentContext
}

type Args []string

// Returns the command line arguments associated with the context.
func (c *Context) Args() Args {
	args := Args(c.flagSet.Args())
	return args
}

// Returns the nth argument, or else a blank string
func (a Args) Get(n int) string {
	if len(a) > n {
		return a[n]
	}
	return ""
}

// Returns the first argument, or else a blank string
func (a Args) First() string {
	return a.Get(0)
}

// Return the rest of the arguments (not the first one)
// or else an empty string slice
func (a Args) Tail() []string {
	if len(a) >= 2 {
		return []string(a)[1:]
	}
	return []string{}
}

// Checks if there are any arguments present
func (a Args) Present() bool {
	return len(a) != 0
}

// Swaps arguments at the given indexes
func (a Args) Swap(from, to int) error {
	if from >= len(a) || to >= len(a) {
		return errors.New("index out of range")
	}
	a[from], a[to] = a[to], a[from]
	return nil
}

func lookupGlobalFlagSet(name string, ctx *Context) *flag.FlagSet {
	if ctx.parentContext != nil {
		ctx = ctx.parentContext
	}
	for ; ctx != nil; ctx = ctx.parentContext {
		if f := ctx.flagSet.Lookup(name); f != nil {
			return ctx.flagSet
		}
	}
	return nil
}

func lookupInt(name string, set *flag.FlagSet) int {
	f := set.Lookup(name)
	if f != nil {
		val, err := strconv.Atoi(f.Value.String())
		if err != nil {
			return 0
		}
		return val
	}

	return 0
}

func lookupDuration(name string, set *flag.FlagSet) time.Duration {
	f := set.Lookup(name)
	if f != nil {
		val, err := time.ParseDuration(f.Value.String())
		if err == nil {
			return val
		}
	}

	return 0
}

func lookupFloat64(name string, set *flag.FlagSet) float64 {
	f := set.Lookup(name)
	if f != nil {
		val, err := strconv.ParseFloat(f.Value.String(), 64)
		if err != nil {
			return 0
		}
		return val
	}

	return 0
}

func lookupString(name string, set *flag.FlagSet) string {
	f := set.Lookup(name)
	if f != nil {
		return f.Value.String()
	}

	return ""
}

func lookupStringSlice(name string, set *flag.FlagSet) []string {
	f := set.Lookup(name)
	if f != nil {
		return (f.Value.(*StringSlice)).Value()

	}

	return nil
}

func lookupIntSlice(name string, set *flag.FlagSet) []int {
	f := set.Lookup(name)
	if f != nil {
		return (f.Value.(*IntSlice)).Value()

	}

	return nil
}

func lookupGeneric(name string, set *flag.FlagSet) interface{} {
	f := set.Lookup(name)
	if f != nil {
		return f.Value
	}
	return nil
}

func lookupBool(name string, set *flag.FlagSet) bool {
	f := set.Lookup(name)
	if f != nil {
		val, err := strconv.ParseBool(f.Value.String())
		if err != nil {
			return false
		}
		return val
	}

	return false
}

func lookupBoolT(name string, set *flag.FlagSet) bool {
	f := set.Lookup(name)
	if f != nil {
		val, err := strconv.ParseBool(f.Value.String())
		if err != nil {
			return true
		}
		return val
	}

	return false
}

func copyFlag(name string, ff *flag.Flag, set *flag.FlagSet) {
	switch ff.Value.(type) {
	case *StringSlice:
	default:
		set.Set(name, ff.Value.String())
	}
}

func normalizeFlags(flags []Flag, set *flag.FlagSet) error {
	visited := make(map[string]bool)
	set.Visit(func(f *flag.Flag) {
		visited[f.Name] = true
	})
	for _, f := range flags {
		parts := strings.Split(f.getName(), ",")
		if len(parts) == 1 {
			continue
		}
		var ff *flag.Flag
		for _, name := range parts {
			name = strings.Trim(name, " ")
			if visited[name] {
				if ff != nil {
					return errors.New("Cannot use two forms of the same flag: " + name + " " + ff.Name)
				}
				ff = set.Lookup(name)
			}
		}
		if ff == nil {
			continue
		}
		for _, name := range parts {
			name = strings.Trim(name, " ")
			if !visited[name] {
				copyFlag(name, ff, set)
			}
		}
	}
	return nil
}
