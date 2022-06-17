package gexe

import (
	"github.com/vladimirvivien/gexe/exec"
	"github.com/vladimirvivien/gexe/fs"
	"github.com/vladimirvivien/gexe/prog"
	"github.com/vladimirvivien/gexe/vars"
)

// Variables returns variable map for DefaultEcho session
func Variables() *vars.Variables {
	return DefaultEcho.Variables()
}

// Envs declares environment variables using
// a multi-line space-separated list:
//
//     Envs("GOOS=linux GOARCH=amd64")
//
// Environment vars can be used in string values
// using Eval("building for os=$GOOS")
func Envs(val string) *Echo {
	return DefaultEcho.Envs(val)
}

// SetEnv sets a process environment variable.
func SetEnv(name, value string) *Echo {
	return DefaultEcho.SetEnv(name, value)
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
func Vars(val string) *Echo {
	return DefaultEcho.Vars(val)
}

// SetVar declares a session variable.
func SetVar(name, value string) *Echo {
	return DefaultEcho.SetVar(name, value)
}

// Val retrieves a session or environment variable
func Val(name string) string {
	return DefaultEcho.Val(name)
}

// Eval returns the string str with its content expanded
// with variable values i.e. Eval("I am $HOME") returns
// "I am </user/home/path>"
func Eval(str string) string {
	return DefaultEcho.Eval(str)
}

// StartProc executes the command in cmdStr and returns immediately
// without waiting. Information about the running process is stored in *exec.Proc.
func StartProc(cmdStr string) *exec.Proc {
	return DefaultEcho.StartProc(cmdStr)
}

// RunProc executes command in cmdStr and waits for the result.
// It returns a *Proc with information about the executed process.
func RunProc(cmdStr string) *exec.Proc {
	return DefaultEcho.RunProc(cmdStr)
}

// Run executes cmdStr, waits, and returns the result as a string.
func Run(cmdStr string) string {
	return DefaultEcho.Run(cmdStr)
}

// Runout executes command cmdStr and prints out the result
func Runout(cmdStr string) {
	DefaultEcho.Runout(cmdStr)
}

// Read creates an fs.FileReader that
// can be used to read content from files.
func Read(path string) fs.FileReader {
	return DefaultEcho.Read(path)
}

// Write creates an fs.FileWriter that
// can be used to write content to files
func Write(path string) fs.FileWriter {
	return DefaultEcho.Write(path)
}

// Prog returns program information via *prog.Info
func Prog() *prog.Info {
	return DefaultEcho.Prog()
}
