// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

// Runner runs iptables and ip6tables commands with the same binaries and
// xtables lock options as the agent's iptables manager. It lets other
// subsystems that program iptables rules share the manager's backend choice
// instead of picking their own.
//
// Commands run in the network namespace of the calling OS thread, so callers
// may use a Runner from within netns.NetNS.Do to program rules in another
// network namespace.
//
// A Runner must only be used once the hive has started: the iptables cell
// initializes the lock options in its start hook.
type Runner interface {
	// RunIPv4 runs iptables with args and returns its standard output.
	// When the command exits with a non-zero status, the returned error
	// wraps an *exec.ExitError.
	RunIPv4(args ...string) (string, error)

	// RunIPv6 runs ip6tables with args and returns its standard output.
	// When the command exits with a non-zero status, the returned error
	// wraps an *exec.ExitError.
	RunIPv6(args ...string) (string, error)
}

type runner struct {
	ip4tables runnable
	ip6tables runnable
}

func (r runner) RunIPv4(args ...string) (string, error) {
	return r.ip4tables.runProgOutput(args)
}

func (r runner) RunIPv6(args ...string) (string, error) {
	return r.ip6tables.runProgOutput(args)
}
