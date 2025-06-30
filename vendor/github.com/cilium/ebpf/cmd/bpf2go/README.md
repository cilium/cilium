bpf2go
===

`bpf2go` compiles a C source file into eBPF bytecode and then emits a
Go file containing the eBPF. The goal is to avoid loading the
eBPF from disk at runtime and to minimise the amount of manual
work required to interact with eBPF programs. It takes inspiration
from `bpftool gen skeleton`.

Invoke the program using go generate:

    //go:generate go run github.com/cilium/ebpf/cmd/bpf2go foo path/to/src.c -- -I/path/to/include

This will emit `foo_bpfel.go` and `foo_bpfeb.go`, with types using `foo`
as a stem. The two files contain compiled BPF for little and big
endian systems, respectively.

## Environment Variables

You can use environment variables to affect all bpf2go invocations
across a project, e.g. to set specific C flags:

    BPF2GO_CFLAGS="-O2 -g -Wall -Werror $(CFLAGS)" go generate ./...

Alternatively, by exporting `$BPF2GO_CFLAGS` from your build system, you can
control all builds from a single location.

Most bpf2go arguments can be controlled this way. See `bpf2go -h` for an
up-to-date list.

## Generated types

`bpf2go` generates Go types for all map keys and values by default. You can
disable this behaviour using `-no-global-types`. You can add to the set of
types by specifying `-type foo` for each type you'd like to generate.

## Examples

See [examples/kprobe](../../examples/kprobe/main.go) for a fully worked out example.
