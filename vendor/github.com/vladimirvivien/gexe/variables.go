package gexe

import (
	"github.com/vladimirvivien/gexe/vars"
)

// Variables returns the variable mapping for echo session e
func (e *Echo) Variables() *vars.Variables {
	return e.vars
}

// Envs declares environment variables using
// a multi-line space-separated list:
//
//     Envs("GOOS=linux GOARCH=amd64")
//
// Environment vars can be used in string values
// using Eval("building for os=$GOOS")
func (e *Echo) Envs(val string) *Echo {
	vars := e.vars.Envs(val)
	e.err = vars.Err()
	return e
}

// SetEnv sets a global process environment variable.
func (e *Echo) SetEnv(name, value string) *Echo {
	vars := e.vars.SetEnv(name, value)
	e.err = vars.Err()
	return e
}

// Vars declares session-scope variables using
// a multi-line space-separated list:
//
//     Envs("foo=bar platform=amd64")
//
// Session vars can be used in string values
// using Eval("My foo=$foo").
//
// Note that session vars are only available
// for the running process.
func (e *Echo) Vars(val string) *Echo {
	vars := e.vars.Vars(val)
	e.err = vars.Err()
	return e
}

// SetVar declares a session variable.
func (e *Echo) SetVar(name, value string) *Echo {
	vars := e.vars.SetVar(name, value)
	e.err = vars.Err()
	return e
}

// Val retrieves a session or environment variable
func (e *Echo) Val(name string) string {
	return e.vars.Val(name)
}

// Eval returns the string str with its content expanded
// with variable values i.e. Eval("I am $HOME") returns
// "I am </user/home/path>"
func (e *Echo) Eval(str string) string {
	return e.vars.Eval(str)
}
