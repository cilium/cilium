//go:build !windows

package gen

import (
	"errors"
	"fmt"
	"go/build/constraint"
	"maps"
	"runtime"
	"slices"
)

var ErrInvalidTarget = errors.New("unsupported target")

var targetsByGoArch = map[GoArch]Target{
	"386":      {"bpfel", "x86", ""},
	"amd64":    {"bpfel", "x86", ""},
	"arm":      {"bpfel", "arm", ""},
	"arm64":    {"bpfel", "arm64", ""},
	"loong64":  {"bpfel", "loongarch", ""},
	"mips":     {"bpfeb", "mips", ""},
	"mipsle":   {"bpfel", "", ""},
	"mips64":   {"bpfeb", "", ""},
	"mips64le": {"bpfel", "", ""},
	"ppc64":    {"bpfeb", "powerpc", ""},
	"ppc64le":  {"bpfel", "powerpc", ""},
	"riscv64":  {"bpfel", "riscv", ""},
	"s390x":    {"bpfeb", "s390", ""},
	"wasm":     {"bpfel", "", "js"},
}

type Target struct {
	// Clang arch string, used to define the clang -target flag, as per
	// "clang -print-targets".
	clang string
	// Linux arch string, used to define __TARGET_ARCH_xzy macros used by
	// https://github.com/libbpf/libbpf/blob/master/src/bpf_tracing.h
	linux string
	// GOOS override for use during tests.
	goos string
}

// TargetsByGoArch returns all supported targets.
func TargetsByGoArch() map[GoArch]Target {
	return maps.Clone(targetsByGoArch)
}

// IsGeneric returns true if the target will compile to generic BPF.
func (tgt *Target) IsGeneric() bool {
	return tgt.linux == ""
}

// Suffix returns a a string suitable for appending to a file name to
// identify the target.
func (tgt *Target) Suffix() string {
	// The output filename must not match any of the following patterns:
	//
	//     *_GOOS
	//     *_GOARCH
	//     *_GOOS_GOARCH
	//
	// Otherwise it is interpreted as a build constraint by the Go toolchain.
	stem := tgt.clang
	if tgt.linux != "" {
		stem = fmt.Sprintf("%s_%s", tgt.linux, tgt.clang)
	}
	return stem
}

// ObsoleteSuffix returns an obsolete suffix for a subset of targets.
//
// It's used to work around an old bug and should not be used in new code.
func (tgt *Target) ObsoleteSuffix() string {
	if tgt.linux == "" {
		return ""
	}

	return fmt.Sprintf("%s_%s", tgt.clang, tgt.linux)
}

// GoArch is a Go arch string.
//
// See https://go.dev/doc/install/source#environment for valid GOARCHes when
// GOOS=linux.
type GoArch string

type GoArches []GoArch

// Constraints is satisfied when GOARCH is any of the arches.
func (arches GoArches) Constraint() constraint.Expr {
	var archConstraint constraint.Expr
	for _, goarch := range arches {
		tag := &constraint.TagExpr{Tag: string(goarch)}
		archConstraint = orConstraints(archConstraint, tag)
	}
	return archConstraint
}

// FindTarget turns a list of identifiers into targets and their respective
// GoArches.
//
// The following are valid identifiers:
//
//   - bpf: compile generic BPF for host endianness
//   - bpfel: compile generic BPF for little endian
//   - bpfeb: compile generic BPF for big endian
//   - native: compile BPF for host target
//   - $GOARCH: compile BPF for $GOARCH target
//
// Generic BPF can run on any target goarch with the correct endianness,
// but doesn't have access to some arch specific tracing functionality.
func FindTarget(id string) (Target, GoArches, error) {
	switch id {
	case "bpf", "bpfel", "bpfeb":
		var goarches []GoArch
		for arch, archTarget := range targetsByGoArch {
			if archTarget.clang == id {
				// Include tags for all goarches that have the same endianness.
				goarches = append(goarches, arch)
			}
		}
		slices.Sort(goarches)
		return Target{id, "", ""}, goarches, nil

	case "native":
		id = runtime.GOARCH
		fallthrough

	default:
		archTarget, ok := targetsByGoArch[GoArch(id)]
		if !ok || archTarget.linux == "" {
			return Target{}, nil, fmt.Errorf("%q: %w", id, ErrInvalidTarget)
		}

		var goarches []GoArch
		for goarch, lt := range targetsByGoArch {
			if lt == archTarget {
				// Include tags for all goarches that have the same
				// target.
				goarches = append(goarches, goarch)
			}
		}

		slices.Sort(goarches)
		return archTarget, goarches, nil
	}
}

func orConstraints(x, y constraint.Expr) constraint.Expr {
	if x == nil {
		return y
	}

	if y == nil {
		return x
	}

	return &constraint.OrExpr{X: x, Y: y}
}
