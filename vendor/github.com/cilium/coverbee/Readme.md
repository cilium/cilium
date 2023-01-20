# CoverBee
[![Go Reference](https://pkg.go.dev/badge/github.com/cilium/coverbee.svg)](https://pkg.go.dev/github.com/cilium/coverbee)

Code coverage collection tool for eBPF programs. CoverBee can instrument already compiled eBPF programs by giving it
an ELF file. This allows for coverage testing without modifying the existing toolchain.

## Installation

`go install github.com/cilium/coverbee/cmd/coverbee@latest`

## Usage CLI

First, instrument and load the programs in a ELF file by using `coverbee load`. 
All programs will be pinned in the directory specified by `--prog-pin-dir`. 
If `--map-pin-dir` is specified, all maps with with `pinning = LIBBPF_PIN_BY_NAME` set will be pinned in the given map.
If `--map-pin-dir` is not specified, a pin location for the cover-map must be specified with `--covermap-pin`.
The block-list will be written as JSON to a location specified by `--block-list` this file contains translation data
and must be passed to `coverbee cover` afterwards.

```
Instrument all programs in the given ELF file and load them into the kernel

Usage:
  coverbee load {--elf=ELF path} {--prog-pin-dir=path to dir} {--map-pin-dir=path to dir | --covermap-pin=path to covermap} {--block-list=path to blocklist} [flags]

Flags:
      --block-list string     Path where the block-list is stored (contains coverage data to source code mapping, needed when reading from cover map)
      --covermap-pin string   Path to pin for the covermap (created by coverbee containing coverage information)
      --elf string            Path to the ELF file containing the programs
  -h, --help                  help for load
      --log string            Path for ultra-verbose log output
      --map-pin-dir string    Path to the directory containing map pins
      --prog-pin-dir string   Path the directory where the loaded programs will be pinned
      --prog-type string      Explicitly set the program type
```

Then attach the programs or test them with `BPF_TEST_RUN`.

Once done, to inspect the coverage call `coverbee cover`, pass it the same `--map-pin-dir`/`--covermap-pin` and 
`--block-list` as was used for `coverbee load`. Specify a path for the output with `--output` which is html by default
but can also be set to output go-cover for use with other tools by setting `--format go-cover`

```
Collect coverage data and output to file

Usage:
  coverbee cover {--map-pin-dir=path to dir | --covermap-pin=path to covermap} {--block-list=path to blocklist} {--output=path to report output} [flags]

Flags:
      --block-list string     Path where the block-list is stored (contains coverage data to source code mapping, needed when reading from cover map)
      --covermap-pin string   Path to pin for the covermap (created by coverbee containing coverage information)
      --format string         Output format (options: html, go-cover) (default "html")
  -h, --help                  help for cover
      --map-pin-dir string    Path to the directory containing map pins
      --output string         Path to the coverage output
```

Don't forget to clean up the programs by detaching and/or removing the pins.

## Usage as library

1. Load the ELF file using `cilium/ebpf`
2. Perform normal setup(except for loading the programs, maps can be pre-loaded)
3. Call `coverbee.InstrumentAndLoadCollection` instead of using `ebpf.NewCollectionWithOptions`
4. Attach the program or run tests
5. Convert the CFG gotten in step 3 to a block-list with `coverbee.CFGToBlockList`
6. Get the `coverbee_covermap` from the collection and apply its contents to the block-list 
   with `coverbee.ApplyCoverMapToBlockList`
7. Convert the block-list into a go-cover or HTML report file with `coverbee.BlockListToGoCover` or
   `coverbee.BlockListToHTML` respectively

## How does CoverBee work

CoverBee instruments existing compiled eBPF programs in ELF format and load them into the kernel. This instrumentation
will increment numbers in a eBPF map when certain parts of the program are ran. CoverBee uses the kernel verifier logs
to find out which registers and stack slots are not used by the program, and uses these for the instrumentation code.

The contents of the cover-map are be mapped back to the source file via the block-list. This block-list is constructed 
from the control flow graph of the programs and the BTF.ext line information. Then a modified version of `go tool cover`
is used to create HTML reports.

## Limitations / Requirements

* CoverBee requires up to 3 stack slots (24 bytes) available on the stack, programs close to the limit might not pass
  the verifier once instrumented.
* CoverBee adds instructions to the programs, programs close to the instruction or complexity limit of the kernel might
  not pass the verifier once instrumented.
* CoverBee used BTF.ext information to convert instructions to coverage information, ELF files without BTF will not work
* CoverBee requires the source code of the programs to pre present at the same location as at compile time and to 
  contain the same contents. BTF.ext contains line and column offsets to absolute filepaths, changes in path or file 
  contents between compilation and coverage testing might result in invalid or non-working coverage reports.
* CoverBee will add a map named `coverbee_covermap` to the collection, so this name can't be used by the program itself.
