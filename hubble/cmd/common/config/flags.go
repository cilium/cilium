// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package config

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/hubble/pkg/defaults"
)

// Keys can be used to retrieve values from GlobalFlags and ServerFlags (e.g.
// when bound to a viper instance).
const (
	// GlobalFlags keys.
	KeyConfig = "config" // string
	KeyDebug  = "debug"  // bool

	// ServerFlags keys.
	KeyServer            = "server"               // string
	KeyTLS               = "tls"                  // bool
	KeyTLSAllowInsecure  = "tls-allow-insecure"   // bool
	KeyTLSCACertFiles    = "tls-ca-cert-files"    // []string
	KeyTLSClientCertFile = "tls-client-cert-file" // string
	KeyTLSClientKeyFile  = "tls-client-key-file"  // string
	KeyTLSServerName     = "tls-server-name"      // string
	KeyBasicAuthUsername = "basic-auth-username"  // string
	KeyBasicAuthPassword = "basic-auth-password"  // string
	KeyTimeout           = "timeout"              // time.Duration
	KeyRequestTimeout    = "request-timeout"      // time.Duration
	KeyPortForward       = "port-forward"         // bool
	KeyPortForwardPort   = "port-forward-port"    // uint16
	KeyKubeContext       = "kube-context"         // string
	KeyKubeNamespace     = "kube-namespace"       // string
	KeyKubeconfig        = "kubeconfig"           // string
)

// GlobalFlags are flags that apply to any command.
var GlobalFlags = pflag.NewFlagSet("global", pflag.ContinueOnError)

// ServerFlags are flags that configure how to connect to a Hubble server.
var ServerFlags = pflag.NewFlagSet("server", pflag.ContinueOnError)

func init() {
	initGlobalFlags()
	initServerFlags()
}

func initGlobalFlags() {
	GlobalFlags.String(KeyConfig, defaults.ConfigFile, "Optional config file")
	GlobalFlags.BoolP(KeyDebug, "D", false, "Enable debug messages")
}

func initServerFlags() {
	ServerFlags.String(KeyServer, defaults.ServerAddress, "Address of a Hubble server. Ignored when --input-file or --port-forward is provided.")
	ServerFlags.Duration(KeyTimeout, defaults.DialTimeout, "Hubble server dialing timeout")
	ServerFlags.Duration(KeyRequestTimeout, defaults.RequestTimeout, "Unary Request timeout. Only applies to non-streaming RPCs (ServerStatus, ListNodes, ListNamespaces).")
	ServerFlags.Bool(
		KeyTLS,
		false,
		"Specify that TLS must be used when establishing a connection to a Hubble server.\r\n"+
			"By default, TLS is only enabled if the server address starts with 'tls://'.",
	)
	ServerFlags.Bool(
		KeyTLSAllowInsecure,
		false,
		"Allows the client to skip verifying the server's certificate chain and host name.\r\n"+
			"This option is NOT recommended as, in this mode, TLS is susceptible to machine-in-the-middle attacks.\r\n"+
			"See also the 'tls-server-name' option which allows setting the server name.",
	)
	ServerFlags.StringSlice(
		KeyTLSCACertFiles,
		nil,
		"Paths to custom Certificate Authority (CA) certificate files."+
			"The files must contain PEM encoded data.",
	)
	ServerFlags.String(
		KeyTLSClientCertFile,
		"",
		"Path to the public key file for the client certificate to connect to a Hubble server (implies TLS).\r\n"+
			"The file must contain PEM encoded data.",
	)
	ServerFlags.String(
		KeyTLSClientKeyFile,
		"",
		"Path to the private key file for the client certificate to connect a Hubble server (implies TLS).\r\n"+
			"The file must contain PEM encoded data.",
	)
	ServerFlags.String(
		KeyTLSServerName,
		"",
		"Specify a server name to verify the hostname on the returned certificate (eg: 'instance.hubble-relay.cilium.io').",
	)
	ServerFlags.String(
		KeyBasicAuthUsername,
		"",
		"Specify a username for basic auth",
	)
	ServerFlags.String(
		KeyBasicAuthPassword,
		"",
		"Specify a password for basic auth",
	)
	ServerFlags.BoolP(
		KeyPortForward,
		"P",
		false,
		"Automatically forward the relay port to the local machine. Analoguous to running: 'cilium hubble port-forward'.",
	)
	ServerFlags.Uint16(
		KeyPortForwardPort,
		4245,
		"Local port to forward to. 0 will select a random port. This option is only considered when --port-forward is set.",
	)
	ServerFlags.String(
		KeyKubeContext,
		"",
		"Kubernetes configuration context. This option is only considered when --port-forward is set.",
	)
	ServerFlags.String(
		KeyKubeNamespace,
		"kube-system",
		"Namespace Cilium is running in. This option is only considered when --port-forward is set.",
	)
	ServerFlags.String(
		KeyKubeconfig,
		"",
		"Path to the kubeconfig file. This option is only considered when --port-forward is set.",
	)
}
