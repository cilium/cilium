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
	"strconv"
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
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/version"

	log "github.com/Sirupsen/logrus"
	etcdAPI "github.com/coreos/etcd/clientv3"
	"github.com/go-openapi/loads"
	consulAPI "github.com/hashicorp/consul/api"
	flags "github.com/jessevdk/go-flags"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	majorMinKernelVersion         = 4
	minorRecommendedKernelVersion = 9
	minorMinKernelVersion         = 8

	majorMinClangVersion         = 3
	minorRecommendedClangVersion = 9
	minorMinClangVersion         = 8
)

var (
	config = NewConfig()

	// Arguments variables keep in alphabetical order
	bpfRoot            string
	disableConntrack   bool
	enableTracing      bool
	enableLogstash     bool
	k8sLabelsPrefixes  []string
	kvStore            string
	validLabels        []string
	labelPrefixFile    string
	logstashAddr       string
	logstashProbeTimer uint32
	loggers            []string
	nat46prefix        string
	socketPath         string
	v4Prefix           string
	v6Address          string
)

var logOpts = make(map[string]string)
var kvStoreOpts = make(map[string]string)

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

func getMajorMinorVersion(version string) (int, int, error) {
	versions := strings.Split(version, ".")
	if len(versions) < 2 {
		return 0, 0, fmt.Errorf("unable to get version from %q", version)
	}
	majorStr, minorStr := versions[0], versions[1]
	major, err := strconv.Atoi(majorStr)
	if err != nil {
		return 0, 0, fmt.Errorf("unable to get major version from %q", version)
	}
	minor, err := strconv.Atoi(minorStr)
	if err != nil {
		return 0, 0, fmt.Errorf("unable to get minor version from %q", version)
	}
	return major, minor, nil
}

func checkKernelVersion() (int, int, error) {
	kernelVersion, err := exec.Command("uname", "-r").CombinedOutput()
	if err != nil {
		return 0, 0, err
	}
	return getMajorMinorVersion(string(kernelVersion))
}

func checkMinRequirements() {
	kernelMajor, kernelMinor, err := checkKernelVersion()
	if err != nil {
		log.Fatalf("kernel version: NOT OK: %s", err)
	}
	if kernelMajor < majorMinKernelVersion ||
		(kernelMajor == majorMinKernelVersion && kernelMinor < minorMinKernelVersion) {
		log.Fatalf("kernel version: NOT OK: minimal supported kernel "+
			"version is >= %d.%d; kernel version that is running is: %d.%d", majorMinKernelVersion, minorMinKernelVersion, kernelMajor, kernelMinor)
	}

	clangVersion, err := exec.Command("clang", "--version").CombinedOutput()
	if err != nil {
		log.Fatalf("clang version: NOT OK: %s", err)
	}
	res := regexp.MustCompile(`(clang version )([^ ]*)`).FindStringSubmatch(string(clangVersion))
	if len(res) != 3 {
		log.Fatalf("clang version: NOT OK: unable to get clang's version "+
			"number from: %q", string(clangVersion))
	}
	clangMajor, clangMinor, err := getMajorMinorVersion(res[2])
	if err != nil {
		log.Fatalf("clang version: NOT OK: %s", err)
	}
	if clangMajor < majorMinClangVersion ||
		(clangMajor == majorMinClangVersion && clangMinor < minorMinClangVersion) {
		log.Fatalf("clang version: NOT OK: minimal supported clang version is "+
			">= %d.%d", majorMinClangVersion, minorMinClangVersion)
	}
	//clang >= 3.9 / kernel < 4.9 - does not work
	if ((clangMajor == majorMinClangVersion && clangMinor > minorMinClangVersion) ||
		clangMajor > majorMinClangVersion) &&
		((kernelMajor < majorMinKernelVersion) ||
			(kernelMajor == majorMinKernelVersion && kernelMinor < minorRecommendedKernelVersion)) {
		log.Fatalf("clang and kernel version: NOT OK: please upgrade "+
			"your kernel version to at least %d.%d", majorMinKernelVersion,
			minorRecommendedKernelVersion)
	}
	log.Infof("clang and kernel versions: OK!")

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
		log.Fatal("linking environment: NOT OK, please make sure you have 'glibc-devel.i686' if you use fedora system or 'libc6-dev-i386' if you use ubuntu system")
	}
	if _, err := os.Stat("/usr/include/sys/cdefs.h"); os.IsNotExist(err) {
		log.Fatal("linking environment: NOT OK, please make sure you have 'libc6-dev-i386' in your ubuntu system")
	}
	log.Info("linking environment: OK!")

	// Checking for bpf_features
	globalsDir := filepath.Join(config.StateDir, "globals")
	if err := os.MkdirAll(globalsDir, defaults.StateDirRights); err != nil {
		log.Fatalf("Could not create runtime directory %q: %s", globalsDir, err)
	}
	if err := os.Chdir(config.LibDir); err != nil {
		log.Fatalf("Could not change to runtime directory %q: %s",
			config.LibDir, err)
	}
	probeScript := filepath.Join(config.BpfDir, "run_probes.sh")
	if err := exec.Command(probeScript, config.BpfDir, config.StateDir).Run(); err != nil {
		log.Fatalf("BPF Verifier: NOT OK. Unable to run checker for bpf_features: %s", err)
	}
	if _, err := os.Stat(filepath.Join(globalsDir, "bpf_features.h")); os.IsNotExist(err) {
		log.Fatalf("BPF Verifier: NOT OK. Unable to read bpf_features.h: %s", err)
	}
	bpfLogPath := filepath.Join(config.StateDir, "bpf_features.log")
	if _, err := os.Stat(bpfLogPath); os.IsNotExist(err) {
		log.Infof("BPF Verifier: OK!")
	} else if err == nil {
		bpfFeaturesLog, err := ioutil.ReadFile(bpfLogPath)
		if err != nil {
			log.Fatalf("BPF Verifier: NOT OK. Unable to read %q: %s", bpfLogPath, err)
		}
		log.Infof("BPF Verifier: NOT OK:\n%s", string(bpfFeaturesLog))
	} else {
		log.Fatalf("BPF Verifier: NOT OK. Unable to read %q: %s", bpfLogPath, err)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	flags := RootCmd.Flags()
	flags.StringVar(&cfgFile, "config", "", "config file (default is $HOME/ciliumd.yaml)")
	flags.BoolP("debug", "D", false, "Enable debug messages")

	flags.StringVarP(&config.Device, "device", "d", "undefined", "Device to snoop on")
	flags.BoolVar(&disableConntrack, "disable-conntrack", false, "Disable connection tracking")
	flags.StringVar(&config.EnablePolicy, "enable-policy", endpoint.DefaultEnforcement, "Enable policy enforcement")
	flags.StringVarP(&config.DockerEndpoint, "docker", "e", "unix:///var/run/docker.sock",
		"Register a listener for docker events on the given endpoint")
	flags.BoolVar(&enableTracing, "enable-tracing", false, "Enable tracing while determining policy")
	flags.StringVar(&nat46prefix, "nat46-range", addressing.DefaultNAT46Prefix,
		"IPv6 prefix to map IPv4 addresses to")
	flags.StringVar(&config.K8sEndpoint, "k8s-api-server", "", "Kubernetes api address server")
	flags.StringVar(&config.K8sCfgPath, "k8s-kubeconfig-path", "", "Absolute path to the kubeconfig file")
	flags.StringSliceVar(&k8sLabelsPrefixes, "k8s-prefix", []string{},
		"Key values that will be read from kubernetes. (Default: k8s-app, version)")
	flags.StringVar(&config.AllowLocalhost, "allow-localhost", AllowLocalhostAuto,
		"Policy when to allow local stack to reach local endpoints { auto | always | policy } ")
	flags.StringVar(&kvStore, "kvstore", kvstore.Local, "Key-value store type")
	flags.Var(common.NewNamedMapOptions("kvstore-opts", &kvStoreOpts, nil), "kvstore-opt", "key-value store options")
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
	flags.StringVar(&config.LibDir, "lib-dir", defaults.LibraryPath, "Path to store runtime build environment")
	flags.StringVar(&socketPath, "socket-path", defaults.SockPath, "Sets the socket path to listen for connections")
	flags.StringVar(&config.LBInterface, "lb", "",
		"Enables load balancer mode where load balancer bpf program is attached to the given interface")
	flags.BoolVar(&config.IPv4Disabled, "disable-ipv4", false, "Disable IPv4 mode")
	flags.StringVar(&v4Prefix, "ipv4-range", "", "IPv4 prefix")
	flags.StringVarP(&config.Tunnel, "tunnel", "t", "vxlan", "Tunnel mode vxlan or geneve, vxlan is the default")
	flags.StringVar(&bpfRoot, "bpf-root", "", "Path to mounted BPF filesystem")
	flags.String("access-log", "", "Path to access log of all HTTP requests observed")
	flags.Bool("version", false, "Print version information")
	flags.StringSliceVar(&loggers, "log-driver", []string{}, "logging endpoints to use")
	flags.Var(common.NewNamedMapOptions("log-opts", &logOpts, nil), "log-opt", "log driver options for cilium")
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
	if viper.GetBool("version") {
		fmt.Printf("Cilium %s\n", version.Version)
		os.Exit(0)
	}

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

	common.RequireRootPrivilege("cilium-agent")

	log.Info("     _ _ _")
	log.Info(" ___|_| |_|_ _ _____")
	log.Info("|  _| | | | | |     |")
	log.Info("|___|_|_|_|___|_|_|_|")
	log.Infof("Cilium %s", version.Version)

	if config.IPv4Disabled {
		endpoint.IPv4Enabled = false
	}

	config.BpfDir = filepath.Join(config.LibDir, defaults.BpfDir)
	if err := os.MkdirAll(config.RunDir, defaults.RuntimePathRights); err != nil {
		log.Fatalf("Could not create runtime directory %q: %s", config.RunDir, err)
	}

	config.StateDir = filepath.Join(config.RunDir, defaults.StateDir)
	if err := os.MkdirAll(config.StateDir, defaults.StateDirRights); err != nil {
		log.Fatalf("Could not create state directory %q: %s", config.StateDir, err)
	}

	if err := os.MkdirAll(config.LibDir, defaults.RuntimePathRights); err != nil {
		log.Fatalf("Could not create library directory %q: %s", config.LibDir, err)
	}
	if !config.KeepTemplates {
		if err := RestoreAssets(config.LibDir, defaults.BpfDir); err != nil {
			log.Fatalf("Unable to restore agent assets: %s", err)
		}
		// Restore permissions of executable files
		if err := RestoreExecPermissions(config.LibDir, `.*\.sh`); err != nil {
			log.Fatalf("Unable to restore agent assets: %s", err)
		}
	}
	checkMinRequirements()

	config.AllowLocalhost = strings.ToLower(config.AllowLocalhost)
	switch config.AllowLocalhost {
	case AllowLocalhostAlways:
		config.alwaysAllowLocalhost = true
	case AllowLocalhostAuto, AllowLocalhostPolicy:
		config.alwaysAllowLocalhost = false
	default:
		log.Fatalf("Invalid setting for --allow-localhost, must be { %s, %s, %s }",
			AllowLocalhostAuto, AllowLocalhostAlways, AllowLocalhostPolicy)
	}
}

// SetupKvStore sets up the key-value store specified in kvStore and configures
// it with the options provided in kvStoreOpts.
func SetupKvStore(kvStore string, kvStoreOpts map[string]string) error {
	var err error
	switch kvStore {
	case kvstore.Etcd:
		err = kvstore.ValidateOpts(kvStore, kvStoreOpts, kvstore.EtcdOpts)
		if err != nil {
			return err
		}
		etcdAddr, ok := kvStoreOpts[kvstore.EAddr]
		etcdConfig, ok2 := kvStoreOpts[kvstore.ECfg]
		if ok || ok2 {
			config.EtcdConfig = &etcdAPI.Config{}
			config.EtcdCfgPath = etcdConfig
			config.EtcdConfig.Endpoints = []string{etcdAddr}
		} else {
			return fmt.Errorf("invalid configuration for etcd provided; please specify an etcd configuration path with --log-opt %s=<path> or an etcd agent address with --log-opt %s=<address>", kvstore.ECfg, kvstore.EAddr)
		}
	case kvstore.Consul:
		err = kvstore.ValidateOpts(kvStore, kvStoreOpts, kvstore.ConsulOpts)
		if err != nil {
			return err
		}
		consulAddr, ok := kvStoreOpts[kvstore.CAddr]
		if ok {
			consulDefaultAPI := consulAPI.DefaultConfig()
			consulSplitAddr := strings.Split(consulAddr, "://")
			if len(consulSplitAddr) == 2 {
				consulAddr = consulSplitAddr[1]
			} else if len(consulSplitAddr) == 1 {
				consulAddr = consulSplitAddr[0]
			}
			consulDefaultAPI.Address = consulAddr
			config.ConsulConfig = consulDefaultAPI
		} else {
			return fmt.Errorf("invalid configuration for consul provided; please specify the address to a consul instance with --kvstore-opt %s=<consul address> option", kvstore.CAddr)
		}
	case kvstore.Local:
		// Local storage doesn't take any configuration, but we want to
		// make sure user is not passing configuration for other types of kvstores.
		err = kvstore.ValidateOpts(kvStore, kvStoreOpts, map[string]bool{})
		if err != nil {
			return err
		}
		log.Infof("Using local storage for key-value store")
	default:
		return fmt.Errorf("unsupported key-value store %q provided", kvStore)
	}
	config.KVStore = kvStore

	return nil
}

func initEnv() {
	common.SetupLogging(loggers, logOpts, "cilium-agent", viper.GetBool("debug"))

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

	if viper.GetBool("debug") {
		config.Opts.Set(endpoint.OptionDebug, true)
	}

	config.Opts.Set(endpoint.OptionDropNotify, true)
	config.Opts.Set(options.PolicyTracing, enableTracing)
	config.Opts.Set(endpoint.OptionConntrack, !disableConntrack)
	config.Opts.Set(endpoint.OptionConntrackAccounting, !disableConntrack)
	config.Opts.Set(endpoint.OptionConntrackLocal, false)

	config.EnablePolicy = strings.ToLower(config.EnablePolicy)

	switch config.EnablePolicy {
	case endpoint.DefaultEnforcement:
		config.Opts.Set(endpoint.OptionPolicy, false)
	case endpoint.NeverEnforce:
		config.Opts.Set(endpoint.OptionPolicy, false)
	case endpoint.AlwaysEnforce:
		config.Opts.Set(endpoint.OptionPolicy, true)
	default:
		log.Fatalf("invalid value for enable-policy %q provided. Supported values: %s, %s, %s.", config.EnablePolicy, endpoint.DefaultEnforcement, endpoint.NeverEnforce, endpoint.AlwaysEnforce)
	}

	err := SetupKvStore(kvStore, kvStoreOpts)
	if err != nil {
		log.Fatalf("Unable to setup kvstore: %s\n", err)
	}

	if p, err := labels.ParseLabelPrefixCfg(validLabels, labelPrefixFile); err != nil {
		log.Fatalf("%s", err)
	} else {
		config.ValidLabelPrefixes = p
	}

	if len(k8sLabelsPrefixes) == 0 {
		config.ValidK8sLabelPrefixes = labels.DefaultK8sLabelPrefixCfg()
	} else {
		config.ValidK8sLabelPrefixes = &labels.LabelPrefixCfg{}
		for _, prefix := range k8sLabelsPrefixes {
			config.ValidK8sLabelPrefixes.LabelPrefixes = append(
				config.ValidK8sLabelPrefixes.LabelPrefixes,
				&labels.LabelPrefix{Prefix: prefix, Source: k8s.LabelSource},
			)
		}
	}

	log.Infof("Valid label prefix configuration:")
	for _, l := range config.ValidLabelPrefixes.LabelPrefixes {
		log.Infof(" - %s", l)
	}

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
	api.PolicyGetPolicyHandler = newGetPolicyHandler(d)
	api.PolicyPutPolicyHandler = newPutPolicyHandler(d)
	api.PolicyDeletePolicyHandler = newDeletePolicyHandler(d)

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
