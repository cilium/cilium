#!/usr/bin/env bash

ruby ../../CMock/lib/cmock.rb -obpf.yaml helpers.h
ruby ../../CMock/lib/cmock.rb -obpf.yaml helpers_skb.h
ruby ../../CMock/lib/cmock.rb -obpf.yaml helpers_xdp.h
