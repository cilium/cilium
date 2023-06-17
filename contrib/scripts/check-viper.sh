#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

# Check that viper's default instance is not used in the agent or operator.
if grep -r -E -i --include \*.go "viper\.(Set|Get[^V])" pkg daemon operator clustermesh-apiserver; then
  echo "Found viper.(Get|Set)* usage. Please use viper.New() or the hive.Viper() instance instead.";
  exit 1
fi

# Check for unwanted API usage.

# viper.GetStringMapString
# Related upstream issue https://github.com/spf13/viper/issues/911
if grep -r -E --exclude-dir={.git,_build,vendor,contrib} -i --include \*.go "(viper|[vV]p)\.GetStringMapString" .; then
  echo "Found viper.GetStringMapString(key) usage. Please use command.GetStringMapString(vp, key) instead";
  exit 1
fi

if grep -r --exclude-dir={.git,_build,vendor,contrib} -i --include \*.go "StringToStringVar" .; then
  echo "Found flags.StringToStringVar usage. Please use option.NewNamedMapOptions instead";
  exit 1
fi

# viper.GetIntSlice
# Related Cilium issue https://github.com/cilium/cilium/issues/20173 and companion PR https://github.com/cilium/cilium/pull/20282
if grep -E -r --exclude-dir={.git,_build,vendor,contrib} -i --include \*.go "(viper|[vV]p).GetIntSlice" .; then
  echo "Found viper.GetIntSlice(key) usage. Please use a flags.StringSlice type and vp.GetStringSlice(key) instead";
  exit 1
fi
