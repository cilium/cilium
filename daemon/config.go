// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"github.com/cilium/cilium/pkg/option"
	"github.com/spf13/viper"
)

func populateConfig() {
	option.Config.Tunnel = viper.GetString(option.TunnelName)
	option.Config.ClusterName = viper.GetString(option.ClusterName)
	option.Config.ClusterID = viper.GetInt(option.ClusterIDName)
	option.Config.ClusterMeshConfig = viper.GetString(option.ClusterMeshConfigName)
	option.Config.CTMapEntriesGlobalTCP = viper.GetInt(option.CTMapEntriesGlobalTCPName)
	option.Config.CTMapEntriesGlobalAny = viper.GetInt(option.CTMapEntriesGlobalAnyName)
	option.Config.UseSingleClusterRoute = viper.GetBool(option.SingleClusterRouteName)
	option.Config.HTTP403Message = viper.GetString("http-403-msg")
	option.Config.BPFCompilationDebug = viper.GetBool(option.BPFCompileDebugName)
	option.Config.EnvoyLogPath = viper.GetString("envoy-log")
	option.Config.SockopsEnable = viper.GetBool(option.SockopsEnableName)
	option.Config.PrependIptablesChains = viper.GetBool(option.PrependIptablesChainsName)
}
