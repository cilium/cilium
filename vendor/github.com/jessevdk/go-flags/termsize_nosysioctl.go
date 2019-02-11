// +build plan9 solaris appengine wasm

package flags

func getTerminalColumns() int {
	return 80
}
