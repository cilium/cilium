// Copyright 2016- 2017Authors of Cilium
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
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/server"
	"github.com/cilium/cilium/api/v1/server/restapi"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/daemon/defaults"
	"github.com/cilium/cilium/daemon/options"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"

	etcdAPI "github.com/coreos/etcd/clientv3"
	"github.com/go-openapi/loads"
	consulAPI "github.com/hashicorp/consul/api"
	flags "github.com/jessevdk/go-flags"
	logging "github.com/op/go-logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	config = NewConfig()
	log    = logging.MustGetLogger("cilium")

	// Arguments variables keep in alphabetical order
	consulAddr         string
	disableConntrack   bool
	enablePolicy       bool
	enableTracing      bool
	enableLogstash     bool
	etcdAddr           []string
	k8sLabels          []string
	validLabels        []string
	labelPrefixFile    string
	logstashAddr       string
	logstashProbeTimer uint32
	socketPath         string
	v4Prefix           string
	v6Address          string
	nat46prefix        string
	bpfRoot            string
)

var cfgFile string

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run cilium daemon",
	Run: func(cmd *cobra.Command, args []string) {
		initEnv()
		runDaemon()
	},
}

func main() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func checkMinRequirements() {
	log.Infof("Checking minimal requirements...")
	clangVersion, err := exec.Command("clang", "--version").CombinedOutput()
	if err != nil {
		log.Fatalf("clang 3.8.x version: NOT OK: %s", err)
	}
	if !strings.Contains(string(clangVersion), " 3.8") {
		log.Fatalf("clang 3.8.x version: NOT OK, please install clang version 3.8.x in your system")
	}
	log.Infof("clang 3.8.x version: OK!")
	lccVersion, err := exec.Command("llc", "--version").CombinedOutput()
	if err == nil {
		if strings.Contains(strings.ToLower(string(lccVersion)), "debug") {
			log.Warningf("llc version was compiled in debug mode, expect higher latency!")
		}
	}
	// /usr/include/gnu/stubs-32.h is installed by 'glibc-devel.i686' in fedora
	// /usr/include/sys/cdefs.h is installed by 'libc6-dev-i386' in ubuntu
	// both files exist on both systems but cdefs.h already exists in fedora
	// without 'glibc-devel.i686' so we check for 'stubs-32.h first.
	if _, err := os.Stat("/usr/include/gnu/stubs-32.h"); os.IsNotExist(err) {
		log.Fatalf("libraries: NOT OK, please make sure you have 'glibc-devel.i686' in your system")
	}
	if _, err := os.Stat("/usr/include/sys/cdefs.h"); os.IsNotExist(err) {
		log.Fatalf("libraries: NOT OK, please make sure you have 'libc6-dev-i386' in your system")
	}
	log.Infof("libraries: OK!")

	// Checking for bpf_features
	globalsDir := filepath.Join(config.RunDir, "globals")
	if err := os.MkdirAll(globalsDir, defaults.RuntimePathRights); err != nil {
		log.Fatalf("Could not create runtime directory %q: %s", globalsDir, err)
	}
	if err := os.Chdir(config.RunDir); err != nil {
		log.Fatalf("Could not change to runtime directory %q: %s",
			config.RunDir, err)
	}
	if err := exec.Command("./bpf/run_probes.sh", "./bpf", ".").Run(); err != nil {
		log.Fatalf("BPF Verifier: NOT OK. Unable to run checker for bpf_features: %s", err)
	}
	if _, err := os.Stat(filepath.Join(globalsDir, "bpf_features.h")); os.IsNotExist(err) {
		log.Fatalf("BPF Verifier: NOT OK. Unable to read bpf_features.h: %s", err)
	}
	bpfLogPath := filepath.Join(config.RunDir, "bpf_features.log")
	if _, err := os.Stat(bpfLogPath); os.IsNotExist(err) {
		log.Infof("BPF Verifier: OK!")
	} else if err == nil {
		bpfFeaturesLog, err := ioutil.ReadFile(bpfLogPath)
		if err != nil {
			log.Fatalf("BPF Verifier: NOT OK. Unable to read %q: %s", bpfLogPath, err)
		}
		log.Warningf("BPF Verifier: NOT OK. %s", string(bpfFeaturesLog))
	} else {
		log.Fatalf("BPF Verifier: NOT OK. Unable to read %q: %s", bpfLogPath, err)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	flags := RootCmd.Flags()
	flags.StringVar(&cfgFile, "config", "", "config file (default is $HOME/ciliumd.yaml)")
	flags.BoolP("debug", "D", false, "Enable debug messages")
	flags.StringVar(&consulAddr, "consul", "", "Consul agent address [127.0.0.1:8500]")
	flags.StringVarP(&config.Device, "device", "d", "undefined", "Device to snoop on")
	flags.BoolVar(&disableConntrack, "disable-conntrack", false, "Disable connection tracking")
	flags.BoolVar(&enablePolicy, "enable-policy", false, "Enable policy enforcement")
	flags.StringVarP(&config.DockerEndpoint, "docker", "e", "unix:///var/run/docker.sock",
		"Register a listener for docker events on the given endpoint")
	flags.StringSliceVar(&etcdAddr, "etcd", []string{}, "Etcd agent address [http://127.0.0.1:2379]")
	flags.StringVar(&config.EtcdCfgPath, "etcd-config-path", "", "Absolute path to the etcd configuration file")
	flags.BoolVar(&enableTracing, "enable-tracing", false, "Enable tracing while determining policy")
	flags.StringVar(&nat46prefix, "nat46-range", addressing.DefaultNAT46Prefix,
		"IPv6 prefix to map IPv4 addresses to")
	flags.StringVar(&config.K8sEndpoint, "k8s-api-server", "", "Kubernetes api address server")
	flags.StringVar(&config.K8sCfgPath, "k8s-kubeconfig-path", "", "Absolute path to the kubeconfig file")
	flags.StringSliceVar(&k8sLabels, "k8s-prefix", []string{},
		"Key values that will be read from kubernetes. (Default: k8s-app, version)")
	flags.BoolVar(&config.KeepConfig, "keep-config", false,
		"When restoring state, keeps containers' configuration in place")
	flags.StringVar(&labelPrefixFile, "label-prefix-file", "", "File with valid label prefixes")
	flags.StringSliceVar(&validLabels, "labels", []string{},
		"List of label prefixes used to determine identity of an endpoint")
	flags.BoolVar(&enableLogstash, "logstash", false, "Enable logstash integration")
	flags.StringVar(&logstashAddr, "logstash-agent", "127.0.0.1:8080", "Logstash agent address")
	flags.Uint32Var(&logstashProbeTimer, "logstash-probe-timer", 10, "Logstash probe timer (seconds)")
	flags.StringVarP(&v6Address, "node-address", "n", "", "IPv6 address of node, must be in correct format")
	flags.BoolVar(&config.RestoreState, "restore", false,
		"Restores state, if possible, from previous daemon")
	flags.BoolVar(&config.KeepTemplates, "keep-templates", false,
		"Do not restore template files from binary")
	flags.StringVar(&config.RunDir, "state-dir", defaults.RuntimePath, "Path to directory to store runtime state")
	flags.StringVar(&socketPath, "socket-path", defaults.SockPath, "Sets the socket path to listen for connections")
	flags.StringVar(&config.LBInterface, "lb", "",
		"Enables load balancer mode where load balancer bpf program is attached to the given interface")
	flags.BoolVar(&config.IPv4Disabled, "disable-ipv4", false, "Disable IPv4 mode")
	flags.StringVar(&v4Prefix, "ipv4-range", "", "IPv4 prefix")
	flags.StringVarP(&config.Tunnel, "tunnel", "t", "vxlan", "Tunnel mode vxlan or geneve, vxlan is the default")
	flags.StringVar(&bpfRoot, "bpf-root", "", "Path to mounted BPF filesystem")
	viper.BindPFlags(flags)
}

// RestoreExecPermissions restores file permissions to 0740 of all files inside
// `searchDir` with the given regex `patterns`.
func RestoreExecPermissions(searchDir string, patterns ...string) error {
	fileList := []string{}
	err := filepath.Walk(searchDir, func(path string, f os.FileInfo, err error) error {
		for _, pattern := range patterns {
			if regexp.MustCompile(pattern).MatchString(f.Name()) {
				fileList = append(fileList, path)
				break
			}
		}
		return nil
	})
	for _, fileToChange := range fileList {
		// Changing files permissions to -rwx:r--:---, we are only
		// adding executable permission to the owner and keeping the
		// same permissions stored by go-bindata.
		if err := os.Chmod(fileToChange, os.FileMode(0740)); err != nil {
			return err
		}
	}
	return err
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfgFile)
	}

	viper.SetEnvPrefix("cilium")
	viper.SetConfigName("ciliumd") // name of config file (without extension)
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
	if err := os.MkdirAll(config.RunDir, defaults.RuntimePathRights); err != nil {
		log.Fatalf("Could not create runtime directory %q: %s", config.RunDir, err)
	}
	if !config.KeepTemplates {
		if err := RestoreAssets(config.RunDir, "bpf"); err != nil {
			log.Fatalf("Unable to restore agent assets: %s", err)
		}
		// Restore permissions of executable files
		if err := RestoreExecPermissions(config.RunDir, `.*\.sh`); err != nil {
			log.Fatalf("Unable to restore agent assets: %s", err)
		}
	}
	checkMinRequirements()
}

func initEnv() {
	socketDir := path.Dir(socketPath)
	if err := os.MkdirAll(socketDir, defaults.RuntimePathRights); err != nil {
		log.Fatalf("Cannot mkdir directory %q for cilium socket: %s", socketDir, err)
	}

	if err := os.Remove(socketPath); !os.IsNotExist(err) && err != nil {
		log.Fatalf("Cannot remove existing Cilium sock %q: %s", socketPath, err)
	}

	// The standard operation is to mount the BPF filesystem to the
	// standard location (/sys/fs/bpf). The user may chose to specify
	// the path to an already mounted filesystem instead. This is
	// useful if the daemon is being round inside a namespace and the
	// BPF filesystem is mapped into the slave namespace.
	if bpfRoot != "" {
		bpf.SetMapRoot(bpfRoot)
	} else if err := bpf.MountFS(); err != nil {
		log.Fatalf("Unable to mount BPF filesystem: %s\n", err)
	}

	config.OptsMU.Lock()
	if viper.GetBool("debug") {
		config.Opts.Set(endpoint.OptionDebug, true)
	}

	config.Opts.Set(endpoint.OptionDropNotify, true)
	config.Opts.Set(endpoint.OptionNAT46, true)
	config.Opts.Set(options.PolicyTracing, enableTracing)
	config.Opts.Set(endpoint.OptionConntrack, !disableConntrack)
	config.Opts.Set(endpoint.OptionConntrackAccounting, !disableConntrack)
	config.Opts.Set(endpoint.OptionPolicy, enablePolicy)
	config.OptsMU.Unlock()

	config.ValidLabelPrefixesMU.Lock()
	if labelPrefixFile != "" {
		var err error
		config.ValidLabelPrefixes, err = labels.ReadLabelPrefixCfgFrom(labelPrefixFile)
		if err != nil {
			log.Fatalf("Unable to read label prefix file: %s\n", err)
		}
	} else {
		config.ValidLabelPrefixes = labels.DefaultLabelPrefixCfg()
	}

	if len(k8sLabels) == 0 {
		config.ValidK8sLabelPrefixes = labels.DefaultK8sLabelPrefixCfg()
	} else {
		for _, prefix := range k8sLabels {
			config.ValidK8sLabelPrefixes.LabelPrefixes = append(
				config.ValidK8sLabelPrefixes.LabelPrefixes,
				&labels.LabelPrefix{Prefix: prefix, Source: common.K8sLabelSource},
			)
		}
	}

	for _, label := range validLabels {
		config.ValidLabelPrefixes.Append(labels.ParseLabelPrefix(label))
	}

	log.Infof("Valid label prefix configuration:")
	for _, l := range config.ValidLabelPrefixes.LabelPrefixes {
		log.Infof(" - %s", l)
	}

	config.ValidLabelPrefixesMU.Unlock()

	_, r, err := net.ParseCIDR(nat46prefix)
	if err != nil {
		log.Fatalf("Invalid NAT46 prefix %s: %s", nat46prefix, err)
	}

	config.NAT46Prefix = r

	nodeAddress, err := addressing.NewNodeAddress(v6Address, v4Prefix, config.Device)
	if err != nil {
		log.Fatalf("Unable to parse node address: %s", err)
	}

	config.NodeAddress = nodeAddress

	if config.IsK8sEnabled() && !strings.HasPrefix(config.K8sEndpoint, "http") {
		config.K8sEndpoint = "http://" + config.K8sEndpoint
	}
}

func runDaemon() {
	if consulAddr != "" {
		consulDefaultAPI := consulAPI.DefaultConfig()
		consulSplitAddr := strings.Split(consulAddr, "://")
		if len(consulSplitAddr) == 2 {
			consulAddr = consulSplitAddr[1]
		} else if len(consulSplitAddr) == 1 {
			consulAddr = consulSplitAddr[0]
		}
		consulDefaultAPI.Address = consulAddr
		config.ConsulConfig = consulDefaultAPI
	}
	if len(etcdAddr) != 0 && config.EtcdCfgPath == "" {
		config.EtcdConfig = &etcdAPI.Config{}
		config.EtcdConfig.Endpoints = etcdAddr
	}

	d, err := NewDaemon(config)
	if err != nil {
		log.Fatalf("Error while creating daemon: %s", err)
		return
	}

	if err := d.PolicyInit(); err != nil {
		log.Fatalf("Unable to initialize policy: %s", err)
	}

	d.EnableConntrackGC()

	if enableLogstash {
		go d.EnableLogstash(logstashAddr, int(logstashProbeTimer))
	}

	d.EnableMonitor()

	sinceLastSync := time.Now()
	d.SyncDocker()

	// Register event listener in docker endpoint
	if err := d.EnableDockerEventListener(sinceLastSync); err != nil {
		log.Warningf("Error while enabling docker event watcher %s", err)
	}

	d.EnableKVStoreWatcher(30 * time.Second)

	if err := d.EnableK8sWatcher(5 * time.Minute); err != nil {
		log.Warningf("Error while enabling k8s watcher %s", err)
	}

	d.RunBackgroundContainerSync()

	swaggerSpec, err := loads.Analyzed(server.SwaggerJSON, "")
	if err != nil {
		log.Fatal(err)
	}

	api := restapi.NewCiliumAPI(swaggerSpec)

	api.Logger = log.Infof

	// /healthz/
	api.DaemonGetHealthzHandler = NewGetHealthzHandler(d)

	// /config/
	api.DaemonGetConfigHandler = NewGetConfigHandler(d)
	api.DaemonPatchConfigHandler = NewPatchConfigHandler(d)

	// /endpoint/
	api.EndpointGetEndpointHandler = NewGetEndpointHandler(d)

	// /endpoint/{id}
	api.EndpointGetEndpointIDHandler = NewGetEndpointIDHandler(d)
	api.EndpointPutEndpointIDHandler = NewPutEndpointIDHandler(d)
	api.EndpointPatchEndpointIDHandler = NewPatchEndpointIDHandler(d)
	api.EndpointDeleteEndpointIDHandler = NewDeleteEndpointIDHandler(d)

	// /endpoint/{id}config/
	api.EndpointGetEndpointIDConfigHandler = NewGetEndpointIDConfigHandler(d)
	api.EndpointPatchEndpointIDConfigHandler = NewPatchEndpointIDConfigHandler(d)

	// /endpoint/{id}/labels/
	api.EndpointGetEndpointIDLabelsHandler = NewGetEndpointIDLabelsHandler(d)
	api.EndpointPutEndpointIDLabelsHandler = NewPutEndpointIDLabelsHandler(d)

	// /identity/
	api.PolicyGetIdentityHandler = NewGetIdentityHandler(d)
	api.PolicyGetIdentityIDHandler = NewGetIdentityIDHandler(d)

	// /policy/
	api.PolicyGetPolicyHandler = NewGetPolicyHandler(d)
	// /policy/{path}
	api.PolicyGetPolicyPathHandler = NewGetPolicyPathHandler(d)
	api.PolicyPutPolicyPathHandler = NewPutPolicyPathHandler(d)
	api.PolicyDeletePolicyPathHandler = NewDeletePolicyPathHandler(d)

	// /policy/resolve/
	api.PolicyGetPolicyResolveHandler = NewGetPolicyResolveHandler(d)

	// /service/{id}/
	api.ServiceGetServiceIDHandler = NewGetServiceIDHandler(d)
	api.ServiceDeleteServiceIDHandler = NewDeleteServiceIDHandler(d)
	api.ServicePutServiceIDHandler = NewPutServiceIDHandler(d)

	// /service/
	api.ServiceGetServiceHandler = NewGetServiceHandler(d)

	// /ipam/{ip}/
	api.IPAMPostIPAMHandler = NewPostIPAMHandler(d)
	api.IPAMPostIPAMIPHandler = NewPostIPAMIPHandler(d)
	api.IPAMDeleteIPAMIPHandler = NewDeleteIPAMIPHandler(d)

	server := server.NewServer(api)
	server.EnabledListeners = []string{"unix"}
	server.SocketPath = flags.Filename(socketPath)
	defer server.Shutdown()

	server.ConfigureAPI()

	if err := server.Serve(); err != nil {
		log.Fatal(err)
	}
}
