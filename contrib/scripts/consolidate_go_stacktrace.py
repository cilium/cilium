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
filters = {'lock': ["lock", "Lock(", "RLock(", "Semacquire("]}


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


# When upgrading to Python 3.9 or later, add type hints:
# stack : list[str]
# keywords : list[str]
def filter_keywords(stack, keywords):
    for s in stack:
        for k in keywords:
            if k in s:
                return True
    return False


def skip_paths(line, must_exist, must_not_exist):
    for s in must_exist:
        if s not in line:
            return True
    for s in must_not_exist:
        if s in line:
            return True
    return False

# For stack : list[str], find the first line matching the source
# repository and return the go pkg path for that stack.


def first_target_pkg(stack):
    for s in stack:
        if skip_paths(s, [cilium_source], ['vendor', 'lock']):
            continue

        # Convert the following:
        #         /go/src/github.com/cilium/cilium/daemon/cmd/daemon_main.go:1886 +0x28ee
        # =>
        # daemon/cm
        result = re.sub(
            r'.*{}(.*)/[^.]*\.go.*'.format(cilium_source),
            r'\1',
            s)
        # print('  > found {}'.format(result))
        return result
    fallback = stack[-2].lstrip()
    # print('  > found {}'.format(fallback))
    return 'goroutine initiated from {}'.format(fallback)


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
    parser.add_argument(
        '-f',
        '--filter',
        nargs='?',
        help='Filter by known categories ({})'.format(
            ','.join(filters.keys())))
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
    print('{} unique stack traces'.format(len(consolidated)))
    skipped = dict()
    blocked = dict()
    keywords = None
    if args.filter in filters:
        keywords = filters[args.filter]
    for stack in sorted(
            consolidated.values(),
            key=cmp_to_key(
                lambda a,
                b: len(a) - len(b)),
            reverse=True):
        if keywords is not None:
            if len(stack[0]) == 0:
                continue
            if filter_keywords(stack[0], keywords):
                pkg = first_target_pkg(stack[0])
                if pkg in blocked:
                    blocked[pkg] = blocked[pkg] + 1
                else:
                    blocked[pkg] = 1
            else:
                pkg = first_target_pkg(stack[0])
                if pkg in skipped:
                    skipped[pkg] = skipped[pkg] + 1
                else:
                    skipped[pkg] = 1
                continue
        print("{} occurences. Sample stack trace:".format(len(stack)))
        print("\n".join(stack[0]).replace(cilium_source, source_dir))

    if len(skipped) > 0:
        print('Stacktraces from the following packages were skipped as they do not match {}:'.format(
            keywords), file=sys.stderr)
        for s in sorted(skipped.keys()):
            print(
                '{} ({} goroutines)'.format(
                    s.replace(
                        cilium_source,
                        args.source_dir),
                    skipped[s]),
                file=sys.stderr)
        print(file=sys.stderr)
    if len(blocked) > 0:
        print('The following packages are blocked:')
        for s in blocked:
            print(s.replace(cilium_source, args.source_dir))

    if f != sys.stdin:
        f.close()
