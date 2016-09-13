#!/usr/bin/env bash
set -e
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
root_dir=${dir}/../..

cp -vR ${root_dir}/bpf ${dir}
cp -vR ${root_dir}/cilium ${dir}
cp -vR ${root_dir}/common ${dir}
mkdir -p ${dir}/contrib
cp -vR ${root_dir}/contrib/upstart ${dir}/contrib
cp -vR ${root_dir}/contrib/autocomplete ${dir}/contrib
cp -vR ${root_dir}/daemon ${dir}
cp -vR ${root_dir}/integration ${dir}
cp -vR ${root_dir}/pkg ${dir}
cp -vR ${root_dir}/plugins ${dir}
cp -vR ${root_dir}/vendor ${dir}
cp -v ${root_dir}/Makefile ${dir}
cp -v ${root_dir}/Makefile.defs ${dir}

cp -v ${root_dir}/Dockerfile ${dir}
