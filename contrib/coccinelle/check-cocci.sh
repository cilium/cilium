#!/usr/bin/env bash

make -C bpf coccicheck | tee /tmp/stdout
exit $(grep -c "^* file " /tmp/stdout)
