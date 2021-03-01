#!/usr/bin/env python

# consolidate_go_stacktrace.py collapses a go stacktrace by uniqueing each
# stack. Addresses, goroutine ID and goroutine ages are ignored when determining
# uniqeness. A sample of each unique trace is printed

import re,sys,collections
from functools import cmp_to_key

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

def print_usage():
    print("""usage: {} [-h | path/to/file]
        -h:         This help.
        path/to/file:   Read and parse file with go stacktraces
        '-' or no params: Read and parse stdin""".format(sys.argv[0]))

if __name__ == "__main__":
    # Handle arguments. We only support a file path, or stdin on "-" or no
    # parameter
    infile = sys.argv[1] if len(sys.argv) > 1 else ""
    if infile in ["-h", "help"]:
        print_usage()
        sys.exit(0)
    elif infile in ["-", "", None]:
        f = sys.stdin
    else:
        f = open(infile)

    # collect stacktraces into groups, each keyed by a version of the stack
    # where unwanted fields have been made into sentinels
    consolidated = collections.defaultdict(list)
    for stack in get_stacks(f):
        h = get_hashable_stack_value(stack)
        consolidated[h].append(stack)

    # print count of each unique stack, and a sample, sorted by frequency
    print("{} unique stack traces".format(len(consolidated)))
    for stack in sorted(consolidated.values(), key=cmp_to_key(lambda a,b: len(a)-len(b)), reverse=True):
        print("{} occurences. Sample stack trace:".format(len(stack)))
        print("\n".join(stack[0]))

    if f != sys.stdin:
        f.close()
