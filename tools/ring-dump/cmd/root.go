// Copyright 2017-2018 Authors of Cilium
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
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/monitor/format"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const targetName = "cilium-ring-dump"

var (
	log     = logging.DefaultLogger.WithField(logfields.LogSubsys, targetName)
	logOpts = make(map[string]string)

	targetFile string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   targetName,
	Short: "Cilium Ringbuffer debug tool",
	Long:  `Tool for digging into cilium ringbuffer dumps`,
	Run:   run,
}

// Fatalf prints the Printf formatted message to stderr and exits the program
// Note: os.Exit(1) is not recoverable
func Fatalf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", fmt.Sprintf(msg, args...))
	os.Exit(-1)
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	flags := rootCmd.PersistentFlags()
	flags.BoolP("debug", "D", false, "Enable debug messages")
	viper.BindPFlags(flags)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if viper.GetBool("debug") {
		log.Level = logrus.DebugLevel
	} else {
		log.Level = logrus.InfoLevel
	}
}

func isComma(r rune) bool {
	return r == ','
}

func isArray(r rune) bool {
	return r == '[' || r == ']' || r == ' '
}

func getFields(filename string) (map[string]string, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s", filename)
	}

	// cf. func (e *PerfEvent) DebugDump()
	fields := strings.FieldsFunc(string(data), isComma)
	if fields == nil {
		return nil, fmt.Errorf("couldn't parse %s", filename)
	}
	m := make(map[string]string, len(fields))
	for _, f := range fields {
		tuple := strings.Split(f, ":")
		if len(tuple) != 2 {
			return nil, fmt.Errorf("malformed field: %s", f)
		}
		key := strings.TrimLeft(tuple[0], " ")
		value := strings.TrimLeft(tuple[1], " ")
		m[key] = value
	}

	return m, nil
}

// getBytes converts a string in the format "[0 224 230 ...]" into a byte array
func getBytes(raw string) []byte {
	rawSlice := strings.FieldsFunc(raw, isArray)
	result := make([]byte, len(rawSlice))

	i := 0
	for _, b := range rawSlice {
		fmt.Sscan(b, &result[i])
		i++
	}
	return result
}

func run(cmd *cobra.Command, args []string) {
	// Logging should always be bootstrapped first. Do not add any code above this!
	logging.SetupLogging(viper.GetStringSlice("log-driver"), logOpts, targetName, viper.GetBool("debug"))

	if len(args) < 1 {
		Fatalf("path to ringbuffer dump file must be specified")
	}

	fields, err := getFields(args[0])
	if err != nil {
		Fatalf(err.Error())
	}

	for k, v := range fields {
		if k == "data" {
			log.Info("Found data; will decode this later...")
			continue
		}
		log.Infof("%s: %s", k, []byte(v))
	}

	stateReader := bytes.NewReader(getBytes(fields["state"]))
	state := bpf.ReadState{}
	if err = state.Decode(stateReader); err != nil {
		Fatalf(err.Error())
	}

	rawPage := getBytes(fields["data"])
	pageReader := bytes.NewReader(rawPage)
	page := bpf.PerfEventMmapPage{}
	if err = page.Decode(pageReader); err != nil {
		Fatalf(err.Error())
	}

	fmt.Printf("decoded state: %+v\n", state)
	fmt.Printf("decoded page: %+v\n", page)

	fmt.Printf("Buffer Size = %d\n", page.DataSize)
	fmt.Printf("Head Offset = %d\n", page.DataHead%page.DataSize)
	fmt.Printf("Tail Offset = %d\n", page.DataTail%page.DataSize)

	debugLevel := format.INFO
	if viper.GetBool("debug") {
		debugLevel = format.DEBUG
	}
	formatter := format.NewMonitorFormatter(debugLevel)
	eventReader := bpf.PerfEventFromMemory(&page, rawPage)
	defer eventReader.Disable()
	result := 0
	eventReader.Read(
		func(msg *bpf.PerfEventSample, cpu int) {
			data := msg.DataDirect()
			formatter.FormatSample(data, cpu)
		},
		func(msg *bpf.PerfEventLost, cpu int) {
			format.LostEvent(msg.Lost, cpu)
		},
		func(msg *bpf.PerfEvent) {
			fmt.Printf("Error while iterating:\n%s\n", msg.Debug())
			result = 1
		},
	)
	os.Exit(result)
}
