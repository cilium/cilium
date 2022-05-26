#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

# Simple script to make sure viper.GetStringMapString should not be used.
# Related upstream issue https://github.com/spf13/viper/issues/911
if grep -r --exclude-dir={.git,_build,vendor,contrib} -i --include \*.go "viper.GetStringMapString" .; then
  echo "Found viper.GetStringMapString(key) usage. Please use command.GetStringMapString(viper.GetViper(), key) instead";
  exit 1
fi

if grep -r --exclude-dir={.git,_build,vendor,contrib} -i --include \*.go "StringToStringVar" .; then
  echo "Found flags.StringToStringVar usage. Please use option.NewNamedMapOptions instead";
  exit 1
fi
