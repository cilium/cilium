#!/usr/bin/env bash

ruby ../../CMock/lib/cmock.rb -obpf.yaml mocks/helpers.h
ruby ../../CMock/lib/cmock.rb -obpf.yaml mocks/helpers_skb.h
ruby ../../CMock/lib/cmock.rb -obpf.yaml mocks/helpers_xdp.h
