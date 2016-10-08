#!/usr/bin/env bash
set -e
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
root_dir="${dir}/../.."
dest="$1"

cp -vR "${root_dir}/bpf" "${dest}"
cp -vR "${root_dir}/cilium" "${dest}"
cp -vR "${root_dir}/common" "${dest}"
mkdir -p "${dest}/contrib"
cp -vR "${root_dir}/contrib/systemd" "${dest}/contrib"
cp -vR "${root_dir}/contrib/upstart" "${dest}/contrib"
cp -vR "${root_dir}/contrib/autocomplete" "${dest}/contrib"
cp -vR "${root_dir}/daemon" "${dest}"
cp -vR "${root_dir}/integration" "${dest}"
cp -vR "${root_dir}/pkg" "${dest}"
cp -vR "${root_dir}/plugins" "${dest}"
cp -vR "${root_dir}/vendor" "${dest}"
cp -vR "${root_dir}/Makefile" "${dest}"
cp -vR "${root_dir}/Makefile.defs" "${dest}"
cp -vR "${root_dir}/LICENSE" "${dest}"
cp -vR "${root_dir}/AUTHORS" "${dest}"
cp -vR "${root_dir}/VERSION" "${dest}"
