#!/usr/bin/env python3

# consolidate_go_stacktrace.py collapses a go stacktrace by uniqueing each
# stack. Addresses, goroutine ID and goroutine ages are ignored when determining
# uniqeness. A sample of each unique trace is printed

import re
import sys
import collections
from functools import cmp_to_key
import argparse


cilium_source = '/go/src/github.com/cilium/cilium/'


def get_stacks(f):
    """
    get_stacks parses file f and yields all lines in go stackrace as one array
    """
    accum = []
    for line in f:
        line = line.rstrip()
        if line.startswith("goroutine"):
            yield accum
            accum = []
        else:
            accum.append(line)


# Regexes used to find and remove addresses, ids and age
strip_addresses = re.compile(r"0x[0-9a-fA-F]+")
strip_goroutine_id = re.compile(r"goroutine [0-9]+")
strip_goroutine_time = re.compile(r", [0-9]+ minutes")


def strip_stack(stack):
    """
    strip_stack replaces addresses, goroutine IDs and ages with a fixed sentinel
    """
    stack = [strip_addresses.sub("0x?", l) for l in stack]
    stack = [strip_goroutine_id.sub("?", l) for l in stack]
    stack = [strip_goroutine_time.sub("", l) for l in stack]
    return stack


def get_hashable_stack_value(stack):
    """
    get_hashable_stack_value transforms stack (and array of strings) into
    something that can be used as a map key
    """
    return "".join(strip_stack(stack))


if __name__ == "__main__":
    # Handle arguments. We only support a file path, or stdin on "-" or no
    # parameter
    parser = argparse.ArgumentParser(
        description='Consolidate stacktraces to remove duplicate stacks.')
    parser.add_argument(
        'infile',
        metavar='PATH',
        nargs='?',
        help='Read and parse this file. Specify \'-\' or omit this option for stdin.')
    parser.add_argument(
        '-s',
        '--source-dir',
        default="",
        help='Rewrite Cilium source paths to refer to this directory')
    args = parser.parse_args()

    if args.infile in ["-", "", None]:
        f = sys.stdin
    else:
        f = open(args.infile)

    # collect stacktraces into groups, each keyed by a version of the stack
    # where unwanted fields have been made into sentinels
    consolidated = collections.defaultdict(list)
    for stack in get_stacks(f):
        h = get_hashable_stack_value(stack)
        consolidated[h].append(stack)

    # If --source-dir flag is not specified, strip cilium_source prefix
    # so that Cilium file paths becomes relative.
    # If --source-dir flag is specified, make sure it ends with / and
    # use it to overwrite cilium_source prefix.
    source_dir = args.source_dir
    if source_dir == "":
        source_dir = "./"
    elif source_dir != "" and source_dir[-1] != '/':
        source_dir += "/"

    # print count of each unique stack, and a sample, sorted by frequency
    print("{} unique stack traces".format(len(consolidated)))
    for stack in sorted(
            consolidated.values(),
            key=cmp_to_key(
                lambda a,
                b: len(a) - len(b)),
            reverse=True):
        print("{} occurences. Sample stack trace:".format(len(stack)))
        print("\n".join(stack[0]).replace(cilium_source, source_dir))

    if f != sys.stdin:
        f.close()
