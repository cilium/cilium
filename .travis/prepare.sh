#!/bin/bash

cd ../..
mkdir cilium
mv pchaigno/cilium cilium/cilium
cd cilium/cilium

curl https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
sudo apt-add-repository "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-10 main"
sudo apt-get -qq update
sudo apt-get install -y clang-10 llvm-10

# disable go modules to avoid downloading all dependencies when doing go get
GO111MODULE=off go get golang.org/x/tools/cmd/cover
GO111MODULE=off go get github.com/mattn/goveralls
