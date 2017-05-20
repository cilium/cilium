// Copyright 2017 Authors of Cilium
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

package cmd

import (
	"fmt"
	"os"

	"github.com/cilium/cilium/common"
	clientPkg "github.com/cilium/cilium/pkg/client"

	l "github.com/op/go-logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	client  *clientPkg.Client
	log     = l.MustGetLogger("cilium")
)

const (
	bashCompletionFunc = `__cilium_endpoint()
{
    local cilium_output out
    if cilium_output=$(cilium endpoint list --no-headers 2>/dev/null); then
        out=($(echo "${cilium_output}" | awk '{print $1}'))
        COMPREPLY=( $( compgen -W "${out[*]}" -- "$cur" ) )
    fi
}

__custom_func() {
    case ${last_command} in
        cilium_endpoint_get | cilium_endpoint_config | cilium_endpoint_disconnect | cilium_endpoint_labels | cilium_endpoint_regenerate)
            __cilium_endpoint
            return
            ;;
        *)
            ;;
    esac
}
`
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "cilium",
	Short: "A brief description of your application",
	Long:  `TBD`,
	BashCompletionFunction: bashCompletionFunc,
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	flags := RootCmd.PersistentFlags()
	flags.StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cilium.yaml)")
	flags.BoolP("debug", "D", false, "Enable debug messages")
	flags.StringP("host", "H", "", "URI to server-side API")
	viper.BindPFlags(flags)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfgFile)
	}

	viper.SetEnvPrefix("cilium")
	viper.SetConfigName(".cilium") // name of config file (without extension)
	viper.AddConfigPath("$HOME")   // adding home directory as first search path
	viper.AutomaticEnv()           // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}

	if viper.GetBool("debug") {
		common.SetupLOG(log, "DEBUG")
	} else {
		common.SetupLOG(log, "INFO")
	}

	if cl, err := clientPkg.NewClient(viper.GetString("host")); err != nil {
		Fatalf("Error while creating client: %s\n", err)
	} else {
		client = cl
	}
}
