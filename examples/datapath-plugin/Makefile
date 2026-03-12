# Copyright Authors of Cilium
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

.PHONY: all clean generate image

all: image

generate:
	BPF2GO_CC="clang" BPF2GO_CFLAGS="-O2 -g -Wall -Werror -mcpu=v2" go generate ./

image: generate
	docker build -f Dockerfile ../../
