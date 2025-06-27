//go:build !windows

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/cmd/bpf2go/gen"
)

const helpText = `Usage: %[1]s [options] <ident> <source file> [-- <C flags>]

ident is used as the stem of all generated Go types and functions, and
must be a valid Go identifier.

source is a single C file that is compiled using the specified compiler
(usually some version of clang).

You can pass options to the compiler by appending them after a '--' argument
or by supplying -cflags. Flags passed as arguments take precedence
over flags passed via -cflags. Additionally, the program expands quotation
marks in -cflags. This means that -cflags 'foo "bar baz"' is passed to the
compiler as two arguments "foo" and "bar baz".

The program expects GOPACKAGE to be set in the environment, and should be invoked
via go generate. The generated files are written to the current directory.

Some options take defaults from the environment. Variable name is mentioned
next to the respective option.

Options:

`

func run(stdout io.Writer, args []string) (err error) {
	b2g, err := newB2G(stdout, args)
	switch {
	case err == nil:
		return b2g.convertAll()
	case errors.Is(err, flag.ErrHelp):
		return nil
	default:
		return err
	}
}

type bpf2go struct {
	stdout  io.Writer
	verbose bool
	// Absolute path to a .c file.
	sourceFile string
	// Absolute path to a directory where .go are written
	outputDir string
	// Alternative output stem. If empty, identStem is used.
	outputStem string
	// Suffix in generated file names such as _test.
	outputSuffix string
	// Valid go package name.
	pkg string
	// Valid go identifier.
	identStem string
	// Targets to build for.
	targetArches map[gen.Target]gen.GoArches
	// C compiler.
	cc string
	// Command used to strip DWARF.
	strip            string
	disableStripping bool
	// C flags passed to the compiler.
	cFlags          []string
	skipGlobalTypes bool
	// C types to include in the generated output.
	cTypes cTypes
	// Build tags to be included in the output.
	tags buildTags
	// Base directory of the Makefile. Enables outputting make-style dependencies
	// in .d files.
	makeBase string
}

func (b2g *bpf2go) Debugln(a ...any) {
	if b2g.verbose {
		fmt.Fprintln(b2g.stdout, a...)
	}
}

func newB2G(stdout io.Writer, args []string) (*bpf2go, error) {
	b2g := &bpf2go{
		stdout: stdout,
	}

	fs := flag.NewFlagSet("bpf2go", flag.ContinueOnError)
	fs.BoolVar(&b2g.verbose, "verbose", getBool("V", false), "Enable verbose logging ($V)")
	fs.StringVar(&b2g.cc, "cc", getEnv("BPF2GO_CC", "clang"),
		"`binary` used to compile C to BPF ($BPF2GO_CC)")
	fs.StringVar(&b2g.strip, "strip", getEnv("BPF2GO_STRIP", ""),
		"`binary` used to strip DWARF from compiled BPF ($BPF2GO_STRIP)")
	fs.BoolVar(&b2g.disableStripping, "no-strip", false, "disable stripping of DWARF")
	flagCFlags := fs.String("cflags", getEnv("BPF2GO_CFLAGS", ""),
		"flags passed to the compiler, may contain quoted arguments ($BPF2GO_CFLAGS)")
	fs.Var(&b2g.tags, "tags", "Comma-separated list of Go build tags to include in generated files")
	flagTarget := fs.String("target", "bpfel,bpfeb", "clang target(s) to compile for (comma separated)")
	fs.StringVar(&b2g.makeBase, "makebase", getEnv("BPF2GO_MAKEBASE", ""),
		"write make compatible depinfo files relative to `directory` ($BPF2GO_MAKEBASE)")
	fs.Var(&b2g.cTypes, "type", "`Name` of a type to generate a Go declaration for, may be repeated")
	fs.BoolVar(&b2g.skipGlobalTypes, "no-global-types", false, "Skip generating types for map keys and values, etc.")
	fs.StringVar(&b2g.outputStem, "output-stem", "", "alternative stem for names of generated files (defaults to ident)")
	outputSuffix := ""
	if strings.HasSuffix(getEnv("GOFILE", ""), "_test.go") {
		outputSuffix = "_test"
	}
	fs.StringVar(&b2g.outputSuffix, "output-suffix", outputSuffix,
		"suffix in generated file names such as _test (default based on $GOFILE)")
	outDir := fs.String("output-dir", "", "target directory of generated files (defaults to current directory)")
	outPkg := fs.String("go-package", "", "package for output go file (default as ENV GOPACKAGE)")

	fs.SetOutput(b2g.stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), helpText, fs.Name())
		fs.PrintDefaults()
		fmt.Fprintln(fs.Output())
		printTargets(fs.Output())
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if *outDir == "" {
		var err error
		if *outDir, err = os.Getwd(); err != nil {
			return nil, err
		}
	}
	b2g.outputDir = *outDir

	if *outPkg == "" {
		*outPkg = os.Getenv(gopackageEnv)
	}
	b2g.pkg = *outPkg

	if b2g.pkg == "" {
		return nil, errors.New("missing package, you should either set the go-package flag or the GOPACKAGE env")
	}

	if b2g.cc == "" {
		return nil, errors.New("no compiler specified")
	}

	args, cFlags := splitCFlagsFromArgs(fs.Args())

	if *flagCFlags != "" {
		splitCFlags, err := splitArguments(*flagCFlags)
		if err != nil {
			return nil, err
		}

		// Command line arguments take precedence over C flags
		// from the flag.
		cFlags = append(splitCFlags, cFlags...)
	}

	for _, cFlag := range cFlags {
		if strings.HasPrefix(cFlag, "-M") {
			return nil, fmt.Errorf("use -makebase instead of %q", cFlag)
		}
	}

	b2g.cFlags = cFlags[:len(cFlags):len(cFlags)]

	if len(args) < 2 {
		return nil, errors.New("expected at least two arguments")
	}

	b2g.identStem = args[0]

	sourceFile, err := filepath.Abs(args[1])
	if err != nil {
		return nil, err
	}
	b2g.sourceFile = sourceFile

	if b2g.makeBase != "" {
		b2g.makeBase, err = filepath.Abs(b2g.makeBase)
		if err != nil {
			return nil, err
		}
	}

	if b2g.outputStem != "" && strings.ContainsRune(b2g.outputStem, filepath.Separator) {
		return nil, fmt.Errorf("-output-stem %q must not contain path separation characters", b2g.outputStem)
	}

	if strings.ContainsRune(b2g.outputSuffix, filepath.Separator) {
		return nil, fmt.Errorf("-output-suffix %q must not contain path separation characters", b2g.outputSuffix)
	}

	targetArches := make(map[gen.Target]gen.GoArches)
	for _, tgt := range strings.Split(*flagTarget, ",") {
		target, goarches, err := gen.FindTarget(tgt)
		if err != nil {
			if errors.Is(err, gen.ErrInvalidTarget) {
				printTargets(b2g.stdout)
				fmt.Fprintln(b2g.stdout)
			}
			return nil, err
		}

		targetArches[target] = goarches
	}

	if len(targetArches) == 0 {
		return nil, fmt.Errorf("no targets specified")
	}
	b2g.targetArches = targetArches

	// Try to find a suitable llvm-strip, possibly with a version suffix derived
	// from the clang binary.
	if b2g.strip == "" {
		b2g.strip = "llvm-strip"
		if after, ok := strings.CutPrefix(b2g.cc, "clang"); ok {
			b2g.strip += after
		}
	}

	return b2g, nil
}

// cTypes collects the C type names a user wants to generate Go types for.
//
// Names are guaranteed to be unique, and only a subset of names is accepted so
// that we may extend the flag syntax in the future.
type cTypes []string

var _ flag.Value = (*cTypes)(nil)

func (ct *cTypes) String() string {
	if ct == nil {
		return "[]"
	}
	return fmt.Sprint(*ct)
}

const validCTypeChars = `[a-z0-9_]`

var reValidCType = regexp.MustCompile(`(?i)^` + validCTypeChars + `+$`)

func (ct *cTypes) Set(value string) error {
	if !reValidCType.MatchString(value) {
		return fmt.Errorf("%q contains characters outside of %s", value, validCTypeChars)
	}

	i := sort.SearchStrings(*ct, value)
	if i >= len(*ct) {
		*ct = append(*ct, value)
		return nil
	}

	if (*ct)[i] == value {
		return fmt.Errorf("duplicate type %q", value)
	}

	*ct = append((*ct)[:i], append([]string{value}, (*ct)[i:]...)...)
	return nil
}

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func getBool(key string, defaultVal bool) bool {
	val, ok := os.LookupEnv(key)
	if !ok {
		return defaultVal
	}

	b, err := strconv.ParseBool(val)
	if err != nil {
		return defaultVal
	}

	return b
}

func (b2g *bpf2go) convertAll() (err error) {
	if _, err := os.Stat(b2g.sourceFile); os.IsNotExist(err) {
		return fmt.Errorf("file %s doesn't exist", b2g.sourceFile)
	} else if err != nil {
		return err
	}

	if !b2g.disableStripping {
		b2g.strip, err = exec.LookPath(b2g.strip)
		if err != nil {
			return err
		}
	}

	for target, arches := range b2g.targetArches {
		if err := b2g.convert(target, arches); err != nil {
			return err
		}
	}

	return nil
}

func (b2g *bpf2go) convert(tgt gen.Target, goarches gen.GoArches) (err error) {
	removeOnError := func(f *os.File) {
		if err != nil {
			os.Remove(f.Name())
		}
		f.Close()
	}

	outputStem := b2g.outputStem
	if outputStem == "" {
		outputStem = strings.ToLower(b2g.identStem)
	}

	stem := fmt.Sprintf("%s_%s%s", outputStem, tgt.Suffix(), b2g.outputSuffix)

	absOutPath, err := filepath.Abs(b2g.outputDir)
	if err != nil {
		return err
	}

	objFileName := filepath.Join(absOutPath, stem+".o")

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	archConstraint := goarches.Constraint()
	constraints := andConstraints(archConstraint, b2g.tags.Expr)

	if err := b2g.removeOldOutputFiles(outputStem, tgt); err != nil {
		return fmt.Errorf("remove obsolete output: %w", err)
	}

	var depInput *os.File
	cFlags := slices.Clone(b2g.cFlags)
	if b2g.makeBase != "" {
		depInput, err = os.CreateTemp("", "bpf2go")
		if err != nil {
			return err
		}
		defer depInput.Close()
		defer os.Remove(depInput.Name())

		cFlags = append(cFlags,
			// Output dependency information.
			"-MD",
			// Create phony targets so that deleting a dependency doesn't
			// break the build.
			"-MP",
			// Write it to temporary file
			"-MF"+depInput.Name(),
		)
	}

	err = gen.Compile(gen.CompileArgs{
		CC:               b2g.cc,
		Strip:            b2g.strip,
		DisableStripping: b2g.disableStripping,
		Flags:            cFlags,
		Target:           tgt,
		Workdir:          cwd,
		Source:           b2g.sourceFile,
		Dest:             objFileName,
	})
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}

	if b2g.disableStripping {
		b2g.Debugln("Compiled object", "file", objFileName)
	} else {
		b2g.Debugln("Compiled and stripped object", "file", objFileName)
	}

	spec, err := ebpf.LoadCollectionSpec(objFileName)
	if err != nil {
		return fmt.Errorf("can't load BPF from ELF: %s", err)
	}

	var maps []string
	for name := range spec.Maps {
		// Skip .rodata, .data, .bss, etc. sections
		if !strings.HasPrefix(name, ".") {
			maps = append(maps, name)
		}
	}

	var variables []string
	for name := range spec.Variables {
		variables = append(variables, name)
	}

	var programs []string
	for name := range spec.Programs {
		programs = append(programs, name)
	}

	types, err := collectCTypes(spec.Types, b2g.cTypes)
	if err != nil {
		return fmt.Errorf("collect C types: %w", err)
	}

	if !b2g.skipGlobalTypes {
		types = append(types, gen.CollectGlobalTypes(spec)...)
	}

	// Write out generated go
	goFileName := filepath.Join(absOutPath, stem+".go")
	goFile, err := os.Create(goFileName)
	if err != nil {
		return err
	}
	defer removeOnError(goFile)

	err = gen.Generate(gen.GenerateArgs{
		Package:     b2g.pkg,
		Stem:        b2g.identStem,
		Constraints: constraints,
		Maps:        maps,
		Variables:   variables,
		Programs:    programs,
		Types:       types,
		ObjectFile:  filepath.Base(objFileName),
		Output:      goFile,
	})
	if err != nil {
		return fmt.Errorf("can't write %s: %s", goFileName, err)
	}

	b2g.Debugln("Generated bpf2go binding", "file", goFileName)

	if b2g.makeBase == "" {
		return
	}

	deps, err := parseDependencies(cwd, depInput)
	if err != nil {
		return fmt.Errorf("can't read dependency information: %s", err)
	}

	depFileName := goFileName + ".d"
	depOutput, err := os.Create(depFileName)
	if err != nil {
		return fmt.Errorf("write make dependencies: %w", err)
	}
	defer depOutput.Close()

	// There is always at least a dependency for the main file.
	deps[0].file = goFileName
	if err := adjustDependencies(depOutput, b2g.makeBase, deps); err != nil {
		return fmt.Errorf("can't adjust dependency information: %s", err)
	}

	b2g.Debugln("Wrote dependency", "file", depFileName)

	return nil
}

// removeOldOutputFiles removes output files generated by an old naming scheme.
//
// In the old scheme some linux targets were interpreted as build constraints
// by the go toolchain.
func (b2g *bpf2go) removeOldOutputFiles(outputStem string, tgt gen.Target) error {
	suffix := tgt.ObsoleteSuffix()
	if suffix == "" {
		return nil
	}

	stem := fmt.Sprintf("%s_%s", outputStem, suffix)
	for _, ext := range []string{".o", ".go"} {
		filename := filepath.Join(b2g.outputDir, stem+ext)

		if err := os.Remove(filename); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}

		b2g.Debugln("Removed obsolete output file", "file", filename)
	}

	return nil
}

func printTargets(w io.Writer) {
	var arches []string
	for goarch, archTarget := range gen.TargetsByGoArch() {
		if archTarget.IsGeneric() {
			continue
		}
		arches = append(arches, string(goarch))
	}
	sort.Strings(arches)

	fmt.Fprint(w, "Supported targets:\n")
	fmt.Fprint(w, "\tbpf\n\tbpfel\n\tbpfeb\n")
	for _, arch := range arches {
		fmt.Fprintf(w, "\t%s\n", arch)
	}
}

func collectCTypes(types *btf.Spec, names []string) ([]btf.Type, error) {
	var result []btf.Type
	for _, cType := range names {
		typ, err := types.AnyTypeByName(cType)
		if err != nil {
			return nil, err
		}
		result = append(result, typ)
	}
	return result, nil
}

const gopackageEnv = "GOPACKAGE"

func main() {
	if err := run(os.Stdout, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
