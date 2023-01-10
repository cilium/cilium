#!/usr/bin/env bash

if [ -x /usr/lib/llvm-7/bin/clang ]; then
	echo "/usr/lib/llvm-7"
	exit 0
fi

find / -iname libLLVMBPFCodeGen.a | head -1 | xargs dirname | xargs dirname
