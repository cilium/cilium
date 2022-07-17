#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

# Simple script to make sure that some specific viper APIs are not used.

# viper.GetStringMapString
# Related upstream issue https://github.com/spf13/viper/issues/911
if grep -r --exclude-dir={.git,_build,vendor,contrib} -i --include \*.go "viper.GetStringMapString" .; then
  echo "Found viper.GetStringMapString(key) usage. Please use command.GetStringMapString(viper.GetViper(), key) instead";
  exit 1
fi

if grep -r --exclude-dir={.git,_build,vendor,contrib} -i --include \*.go "StringToStringVar" .; then
  echo "Found flags.StringToStringVar usage. Please use option.NewNamedMapOptions instead";
  exit 1
fi

# viper.GetIntSlice
# Related Cilium issue https://github.com/cilium/cilium/issues/20173 and companion PR https://github.com/cilium/cilium/pull/20282
if grep -r --exclude-dir={.git,_build,vendor,contrib} -i --include \*.go "viper.GetIntSlice" .; then
  echo "Found viper.GetIntSlice(key) usage. Please use a flags.StringSlice type and viper.GetStringSlice(key) instead";
  exit 1
fi
