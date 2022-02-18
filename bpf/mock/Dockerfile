# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
# Copyright Authors of Cilium

FROM docker.io/library/ubuntu:20.04
RUN apt-get update
RUN apt-get -y install build-essential
RUN apt-get -y install clang
RUN apt-get -y install ruby-full
RUN apt-get -y install git
RUN git clone --recursive https://github.com/ThrowTheSwitch/CMock.git
RUN git -C CMock reset --hard 3d4ba8d20b8958da5dace7dd5d31155c94b60819
RUN git clone https://github.com/DavidLeeds/hashmap.git
RUN git -C hashmap reset --hard 137d60b3818c22c79d2be5560150eb2eff981a68
