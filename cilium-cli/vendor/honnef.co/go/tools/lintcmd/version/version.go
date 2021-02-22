package version

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const Version = "2020.2.2"
const MachineVersion = "v0.1.2"

// version returns a version descriptor and reports whether the
// version is a known release.
func version() (human, machine string, known bool) {
	if Version != "devel" {
		return Version, MachineVersion, true
	}
	v, ok := buildInfoVersion()
	if ok {
		return v, "", false
	}
	return "devel", "", false
}

func Print() {
	human, machine, release := version()

	if release {
		fmt.Printf("%s %s (%s)\n", filepath.Base(os.Args[0]), human, machine)
	} else if human == "devel" {
		fmt.Printf("%s (no version)\n", filepath.Base(os.Args[0]))
	} else {
		fmt.Printf("%s (devel, %s)\n", filepath.Base(os.Args[0]), human)
	}
}

func Verbose() {
	Print()
	fmt.Println()
	fmt.Println("Compiled with Go version:", runtime.Version())
	printBuildInfo()
}
