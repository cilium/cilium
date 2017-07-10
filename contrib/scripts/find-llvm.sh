#!/usr/bin/env bash

if [ -x /usr/local/clang/bin/clang ]; then
	echo "/usr/local/clang"
	exit 0
fi

find / -iname libLLVMBPFCodeGen.a | head -1 | xargs dirname | xargs dirname
