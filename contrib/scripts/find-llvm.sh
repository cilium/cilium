#!/usr/bin/env bash
find / -iname libLLVMBPFCodeGen.a | head -1 | xargs dirname | xargs dirname
