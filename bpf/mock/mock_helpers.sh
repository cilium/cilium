#!/usr/bin/env bash
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
# Copyright Authors of Cilium

ruby ../../CMock/lib/cmock.rb -obpf.yaml mocks/helpers.h
ruby ../../CMock/lib/cmock.rb -obpf.yaml mocks/helpers_skb.h
ruby ../../CMock/lib/cmock.rb -obpf.yaml mocks/helpers_xdp.h
