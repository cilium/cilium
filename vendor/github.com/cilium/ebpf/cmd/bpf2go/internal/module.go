package internal

// We used to have some clever code here which relied on debug.ReadBuildInfo().
// This is broken due to https://github.com/golang/go/issues/33976, and some build
// systems like bazel also do not generate the necessary data. Let's keep it
// simple instead.

// The module containing the code in this repository.
const CurrentModule = "github.com/cilium/ebpf"
