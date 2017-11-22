# Envoy bpf metadata listener filter

This project adds Cilium filters to the Envoy binary.

## Building

To build the Envoy static binary:

1. `git submodule update --init`
2. `cd envoy`
3. `bazel build //:envoy`

## Testing

To run the `bpf_metadata` integration test:

`bazel test //:bpf_metadata_integration_test`

To run the regular Envoy tests from this project:

`bazel test @envoy//...`

## How it works

jrajahalme's [Envoy repository](https://github.com/jrajahalme/envoy/) is provided as a submodule.
The [`WORKSPACE`](WORKSPACE) file maps the `@envoy` repository to this local path.

The [`BUILD`](BUILD) file introduces a new Envoy static binary target, `envoy`,
that links together the new filter and `@envoy//source/exe:envoy_main_lib`. The
`bpf_metadata` filter registers itself during the static initialization phase of the
Envoy binary as a new filter.
