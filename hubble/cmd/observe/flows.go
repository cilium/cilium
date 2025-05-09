// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package observe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/hubble/cmd/common/config"
	"github.com/cilium/cilium/hubble/cmd/common/conn"
	"github.com/cilium/cilium/hubble/cmd/common/template"
	"github.com/cilium/cilium/hubble/pkg/defaults"
	"github.com/cilium/cilium/hubble/pkg/logger"
	hubprinter "github.com/cilium/cilium/hubble/pkg/printer"
	hubtime "github.com/cilium/cilium/hubble/pkg/time"
	"github.com/cilium/cilium/pkg/logging/logfields"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

// see protocol filter in Hubble server code (there is unfortunately no
// list of supported protocols defined anywhere)
var protocols = []string{
	// L4
	"icmp", "icmpv4", "icmpv6",
	"sctp",
	"tcp",
	"udp",
	// L7
	"dns",
	"http",
	"kafka",
}

var verdicts = []string{
	flowpb.Verdict_FORWARDED.String(),
	flowpb.Verdict_DROPPED.String(),
	flowpb.Verdict_AUDIT.String(),
	flowpb.Verdict_REDIRECTED.String(),
	flowpb.Verdict_ERROR.String(),
	flowpb.Verdict_TRACED.String(),
	flowpb.Verdict_TRANSLATED.String(),
}

// flowEventTypes are the valid event types supported by observe. This corresponds
// to monitorAPI.MessageTypeNames, excluding MessageTypeNameAgent,
// MessageTypeNameDebug and MessageTypeNameRecCapture. These excluded message
// types are not supported by `hubble observe flows` but have separate
// sub-commands.
var flowEventTypes = []string{
	monitorAPI.MessageTypeNameCapture,
	monitorAPI.MessageTypeNameDrop,
	monitorAPI.MessageTypeNameL7,
	monitorAPI.MessageTypeNamePolicyVerdict,
	monitorAPI.MessageTypeNameTrace,
	monitorAPI.MessageTypeNameTraceSock,
}

// flowEventTypeSubtypes is a map message types and all their subtypes.
var flowEventTypeSubtypes = map[string][]string{
	monitorAPI.MessageTypeNameCapture: nil,
	monitorAPI.MessageTypeNameDrop:    nil,
	monitorAPI.MessageTypeNameTrace: {
		monitorAPI.TraceObservationPoints[monitorAPI.TraceFromLxc],
		monitorAPI.TraceObservationPoints[monitorAPI.TraceFromHost],
		monitorAPI.TraceObservationPoints[monitorAPI.TraceFromNetwork],
		monitorAPI.TraceObservationPoints[monitorAPI.TraceFromOverlay],
		monitorAPI.TraceObservationPoints[monitorAPI.TraceFromProxy],
		monitorAPI.TraceObservationPoints[monitorAPI.TraceFromStack],
		monitorAPI.TraceObservationPoints[monitorAPI.TraceFromCrypto],
		monitorAPI.TraceObservationPoints[monitorAPI.TraceToLxc],
		monitorAPI.TraceObservationPoints[monitorAPI.TraceToHost],
		monitorAPI.TraceObservationPoints[monitorAPI.TraceToNetwork],
		monitorAPI.TraceObservationPoints[monitorAPI.TraceToOverlay],
		monitorAPI.TraceObservationPoints[monitorAPI.TraceToProxy],
		monitorAPI.TraceObservationPoints[monitorAPI.TraceToStack],
		monitorAPI.TraceObservationPoints[monitorAPI.TraceToCrypto],
	},
	monitorAPI.MessageTypeNameL7:            nil,
	monitorAPI.MessageTypeNamePolicyVerdict: nil,
	monitorAPI.MessageTypeNameTraceSock:     nil,
}

const (
	allowlistFlag = "allowlist"
	denylistFlag  = "denylist"
)

// getFlowsFilters struct is only used for printing allowlist/denylist filters as YAML.
type getFlowsFilters struct {
	Allowlist []string `yaml:"allowlist,omitempty"`
	Denylist  []string `yaml:"denylist,omitempty"`
}

// getFlowFiltersYAML returns allowlist/denylist filters as a YAML string. This YAML can then be
// passed to hubble observe command via `--config` flag.
func getFlowFiltersYAML(req *observerpb.GetFlowsRequest) (string, error) {
	var allowlist, denylist []string
	for _, filter := range req.GetWhitelist() {
		filterJSON, err := json.Marshal(filter)
		if err != nil {
			return "", err
		}
		allowlist = append(allowlist, string(filterJSON))

	}
	for _, filter := range req.GetBlacklist() {
		filterJSON, err := json.Marshal(filter)
		if err != nil {
			return "", err
		}
		denylist = append(denylist, string(filterJSON))
	}
	filters := getFlowsFilters{
		Allowlist: allowlist,
		Denylist:  denylist,
	}
	out, err := yaml.Marshal(filters)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// GetHubbleClientFunc is primarily used to mock out the hubble client in some unit tests.
var GetHubbleClientFunc = func(ctx context.Context, vp *viper.Viper) (client observerpb.ObserverClient, cleanup func() error, err error) {
	if otherOpts.inputFile != "" {
		if vp.GetBool(config.KeyPortForward) {
			return nil, nil, fmt.Errorf("cannot use --input-file and --auto-port-forward together")
		}
		var f *os.File
		if otherOpts.inputFile == "-" {
			// read flows from stdin
			f = os.Stdin
			// noop cleanup
			cleanup = func() error { return nil }
		} else {
			// read flows from the provided file
			f, err = os.Open(otherOpts.inputFile)
			if err != nil {
				return nil, nil, err
			}
			cleanup = f.Close
		}
		client = NewIOReaderObserver(f)
		return client, cleanup, nil
	}
	// read flows from a hubble server
	hubbleConn, err := conn.NewWithFlags(ctx, vp)
	if err != nil {
		return nil, nil, err
	}
	logger.Logger.Debug("connected to Hubble API", logfields.Server, config.KeyServer)
	cleanup = hubbleConn.Close
	client = observerpb.NewObserverClient(hubbleConn)
	return client, cleanup, nil
}

type cmdUsage struct {
	use     string
	short   string
	long    string
	example string
}

func newObserveCmd(vp *viper.Viper) *cobra.Command {
	ofilter := newFlowFilter()
	usage := cmdUsage{
		use:   "observe",
		short: "Observe flows and events of a Hubble server",
	}
	return newFlowsCmdHelper(usage, vp, ofilter)
}

func newFlowsCmd(vp *viper.Viper) *cobra.Command {
	ofilter := newFlowFilter()
	return newFlowsCmdWithFilter(vp, ofilter)
}

func newFlowsCmdWithFilter(vp *viper.Viper, ofilter *flowFilter) *cobra.Command {
	usage := cmdUsage{
		example: `* Piping flows to hubble observe

  Save output from 'hubble observe -o jsonpb' command to a file, and pipe it to
  the observe command later for offline processing. For example:

    hubble observe -o jsonpb --last 1000 > flows.json

  Then,

    cat flows.json | hubble observe --input-file -

  Note that the observe command ignores --follow, --last, and server flags when it
  reads flows from stdin. The observe command processes and output flows in the same
  order they are read from stdin without sorting them by timestamp.

* Filtering flows

  Observe provides a long list of filter options. These options let you, for example,
  filter for the used HTTP method using the '--http-method' flag. The following
  command shows all flows that use the HTTP PUT method.

    hubble observe --http-method put

  You can also provide multiple values for a flag, in which case a flow matches the
  filter if it matches any of the provided values. If you add a second '--http-method'
  flag matching GET requests to the previous example, the command will show any flow
  using either a PUT or GET method.

    hubble observe --http-method put --http-method get

  If you add a different flag, a flow is only returned if it matches for both of the
  different flags. For example, you can add a '--to-namespace' flag to the previous
  command so only flows using GET or PUT requests to endpoints in namespace 'foo' are
  returned.

    hubble observe --http-method put --http-method get --to-namespace foo

  And by adding another '--to-namespace' flag, it will return flows using GET or PUT
  requests to endpoints in namespace 'foo' or 'bar'

    hubble observe --http-method put --http-method get --to-namespace foo --to-namespace bar

* Using negations on filters

  Observe can also return all flows that don't match a certain filter by using the
  '--not' flag. The following command returns all flows that don't use the HTTP PUT
  method.

    hubble observe --not --http-method put

  To filter out multiple values, you can combine negative flags by prefixing each of
  them with '--not'. The following command will return all flows that neither use a
  GET nor PUT method.

    hubble observe --not --http-method put --not --http-method get

  You can also filter using multiple different negative flags. The following example
  filters out all flows that match both of the flags. For example, by adding a
  '--not --to-namespace foo' flag, the example command will show all flows that
  don't use a GET or PUT method to endpoints in the 'foo' namespace.

    hubble observe --not --http-method put --not --http-method get --not --to-namespace foo

  This means the command will still return flows to the 'foo' namespace that don't
  use HTTP PUT or GET methods, and it will return flows using HTTP PUT and GET
  methods that end in other namespaces.
  `,
		use:   "flows",
		short: "Observe flows of a Hubble server",
		long: `Observe provides visibility into flow information on the network and
application level. Rich filtering enable observing specific flows related to
individual pods, services, TCP connections, DNS queries, HTTP requests and
more.

Observe can filter flows using multiple different flags, such as filtering for
the source namespace or the protocol used. To match a filter flag, a flow must
match at least one of the provided values for that flag. A flow must match all
the provided filter flags to be returned.

Observe can also show all flows that do not match a provided filter, by adding
the '--not' flag in front of a filter flag. To match a negated filter
flag, a flow must not match any of the provided values for that flag. A returned
flow does not match any of the negated filter flags.
`,
	}

	return newFlowsCmdHelper(usage, vp, ofilter)
}

func newFlowsCmdHelper(usage cmdUsage, vp *viper.Viper, ofilter *flowFilter) *cobra.Command {

	filterFlags := pflag.NewFlagSet("filters", pflag.ContinueOnError)
	rawFilterFlags := pflag.NewFlagSet("raw-filters", pflag.ContinueOnError)
	flowsFormattingFlags := pflag.NewFlagSet("Flow Format", pflag.ContinueOnError)
	flagSets := []*pflag.FlagSet{selectorFlags, filterFlags, rawFilterFlags, formattingFlags, flowsFormattingFlags, config.ServerFlags, otherFlags}

	flowsCmd := &cobra.Command{
		Example: usage.example,
		Use:     usage.use,
		Short:   usage.short,
		Long:    usage.long,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			// bind these flags to viper so that they can be specified as environment variables.
			// We bind these flags during PreRun so that only the running command binds them to the configuration.
			return vp.BindPFlags(rawFilterFlags)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			debug := vp.GetBool(config.KeyDebug)
			if err := handleFlowArgs(cmd.OutOrStdout(), ofilter, debug); err != nil {
				return err
			}
			req, err := getFlowsRequest(ofilter, vp.GetStringSlice(allowlistFlag), vp.GetStringSlice(denylistFlag))
			if err != nil {
				return err
			}
			if otherOpts.printRawFilters {
				filterYAML, err := getFlowFiltersYAML(req)
				if err != nil {
					return err
				}
				fmt.Fprint(cmd.OutOrStdout(), filterYAML)
				return nil
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
			defer cancel()

			client, cleanup, err := GetHubbleClientFunc(ctx, vp)
			if err != nil {
				return err
			}
			defer cleanup()

			logger.Logger.Debug("Sending GetFlows request", logfields.Request, req)
			if err := getFlows(ctx, client, req); err != nil {
				msg := err.Error()
				// extract custom error message from failed grpc call
				if s, ok := status.FromError(err); ok && s.Code() == codes.Unknown {
					msg = s.Message()
				}
				return errors.New(msg)
			}
			return nil
		},
	}

	// filter flags
	filterFlags.Var(filterVar(
		"not", ofilter,
		"Reverses the next filter to be blacklist i.e. --not --from-ip 2.2.2.2"))
	filterFlags.Var(filterVar(
		"uuid", ofilter,
		"Show the only flow matching this unique flow identifier, if any"))
	filterFlags.Var(filterVar(
		"node-name", ofilter,
		`Show all flows which match the given node names (e.g. "k8s*", "test-cluster/*.company.com")`))
	filterFlags.Var(filterVar(
		"node-label", ofilter,
		`Show only flows observed on nodes matching the given label filter (e.g. "key1=value1", "io.cilium/egress-gateway")`))
	filterFlags.Var(filterVar(
		"from-cluster", ofilter,
		"Show all flows originating from endpoints known to be in the given cluster name"))
	filterFlags.Var(filterVar(
		"cluster", ofilter,
		`Show all flows which match the cluster names (e.g. "test-cluster", "prod-*")`))
	filterFlags.Var(filterVar(
		"to-cluster", ofilter,
		"Show all flows destined to endpoints known to be in the given cluster name"))
	filterFlags.Var(filterVar(
		"protocol", ofilter,
		`Show only flows which match the given L4/L7 flow protocol (e.g. "udp", "http")`))
	filterFlags.Var(filterVar(
		"tcp-flags", ofilter,
		`Show only flows which match the given TCP flags (e.g. "syn", "ack", "fin")`))
	filterFlags.VarP(filterVarP(
		"type", "t", ofilter, []string{},
		fmt.Sprintf("Filter by event types TYPE[:SUBTYPE]. Available types and subtypes:\n%s", func() string {
			var b strings.Builder
			w := tabwriter.NewWriter(&b, 0, 0, 1, ' ', 0)
			fmt.Fprintln(w, "TYPE", "\t", "SUBTYPE")
			// we don't iterate the flowEventTypeSubtypes map as we want
			// consistent ordering
			for _, k := range flowEventTypes {
				v := flowEventTypeSubtypes[k]
				if len(v) > 0 {
					fmt.Fprintln(w, k, "\t", v[0])
					for i := 1; i < len(v); i++ {
						fmt.Fprintln(w, "\t", v[i])
					}
				} else {
					fmt.Fprintln(w, k, "\t", "n/a")
				}
			}
			w.Flush()
			return strings.TrimSpace(b.String())
		}())))
	filterFlags.Var(filterVar(
		"verdict", ofilter,
		fmt.Sprintf("Show only flows with this verdict [%s]", strings.Join(verdicts, ", ")),
	))
	filterFlags.Var(filterVar(
		"drop-reason-desc", ofilter,
		`Show only flows which match this drop reason describe (e.g. "POLICY_DENIED", "UNSUPPORTED_L3_PROTOCOL")`))
	filterFlags.Var(filterVar(
		"http-status", ofilter,
		`Show only flows which match this HTTP status code prefix (e.g. "404", "5+")`))
	filterFlags.Var(filterVar(
		"http-method", ofilter,
		`Show only flows which match this HTTP method (e.g. "get", "post")`))
	filterFlags.Var(filterVar(
		"http-path", ofilter,
		`Show only flows which match this HTTP path regular expressions (e.g. "/page/\\d+")`))
	filterFlags.Var(filterVar(
		"http-url", ofilter,
		`Show only flows which match this HTTP URL regular expressions (e.g. "http://.*cilium\.io/page/\\d+")`))
	filterFlags.Var(filterVar(
		"http-header", ofilter,
		`Show only flows which match this HTTP header key:value pairs (e.g. "foo:bar")`))

	filterFlags.Var(filterVar(
		"trace-id", ofilter,
		"Show only flows which match this trace ID"))

	filterFlags.Var(filterVar(
		"from-fqdn", ofilter,
		`Show all flows originating at the given fully qualified domain name (e.g. "*.cilium.io").`))
	filterFlags.Var(filterVar(
		"fqdn", ofilter,
		`Show all flows related to the given fully qualified domain name (e.g. "*.cilium.io").`))
	filterFlags.Var(filterVar(
		"to-fqdn", ofilter,
		`Show all flows terminating at the given fully qualified domain name (e.g. "*.cilium.io").`))

	filterFlags.Var(filterVar(
		"from-ip", ofilter,
		"Show all flows originating at the given IP address. Each of the source IPs can be specified as an exact match (e.g. '1.1.1.1') or as a CIDR range (e.g.'1.1.1.0/24')."))
	filterFlags.Var(filterVar(
		"snat-ip", ofilter,
		"Show all flows SNATed with the given IP address. Each of the SNAT IPs can be specified as an exact match (e.g. '1.1.1.1') or as a CIDR range (e.g.'1.1.1.0/24')."))
	filterFlags.Var(filterVar(
		"ip", ofilter,
		"Show all flows originating or terminating at the given IP address. Each of the IPs can be specified as an exact match (e.g. '1.1.1.1') or as a CIDR range (e.g.'1.1.1.0/24')."))
	filterFlags.Var(filterVar(
		"to-ip", ofilter,
		"Show all flows terminating at the given IP address. Each of the destination IPs can be specified as an exact match (e.g. '1.1.1.1') or as a CIDR range (e.g.'1.1.1.0/24')."))

	filterFlags.VarP(filterVarP(
		"ipv4", "4", ofilter, nil,
		`Show only IPv4 flows`))
	filterFlags.Lookup("ipv4").NoOptDefVal = "v4" // add default val so none is required to be provided
	filterFlags.VarP(filterVarP(
		"ipv6", "6", ofilter, nil,
		`Show only IPv6 flows`))
	filterFlags.Lookup("ipv6").NoOptDefVal = "v6" // add default val so none is required to be provided
	filterFlags.Var(filterVar(
		"ip-version", ofilter,
		`Show only IPv4, IPv6 flows or non IP flows (e.g. ARP packets) (ie: "none", "v4", "v6")`))

	filterFlags.Var(filterVar(
		"from-pod", ofilter,
		"Show all flows originating in the given pod name prefix([namespace/]<pod-name>). If namespace is not provided, 'default' is used"))
	filterFlags.Var(filterVar(
		"pod", ofilter,
		"Show all flows related to the given pod name prefix ([namespace/]<pod-name>). If namespace is not provided, 'default' is used."))
	filterFlags.Var(filterVar(
		"to-pod", ofilter,
		"Show all flows terminating in the given pod name prefix([namespace/]<pod-name>). If namespace is not provided, 'default' is used"))

	filterFlags.Var(filterVar(
		"from-namespace", ofilter,
		"Show all flows originating in the given Kubernetes namespace."))
	filterFlags.VarP(filterVarP(
		"namespace", "n", ofilter, nil,
		"Show all flows related to the given Kubernetes namespace."))
	filterFlags.Var(filterVar(
		"to-namespace", ofilter,
		"Show all flows terminating in the given Kubernetes namespace."))

	filterFlags.Var(filterVar(
		"from-all-namespaces", ofilter,
		"Show flows originating in any Kubernetes namespace."))
	filterFlags.Lookup("from-all-namespaces").NoOptDefVal = "true" // add default val so none is required to be provided
	filterFlags.VarP(filterVarP(
		"all-namespaces", "A", ofilter, nil,
		"Show all flows in any Kubernetes namespace."))
	filterFlags.Lookup("all-namespaces").NoOptDefVal = "true" // add default val so none is required to be provided
	filterFlags.Var(filterVar(
		"to-all-namespaces", ofilter,
		"Show flows terminating in any Kubernetes namespace."))
	filterFlags.Lookup("to-all-namespaces").NoOptDefVal = "true" // add default val so none is required to be provided

	filterFlags.Var(filterVar(
		"from-label", ofilter,
		`Show only flows originating in an endpoint with the given labels (e.g. "key1=value1", "reserved:world")`))
	filterFlags.VarP(filterVarP(
		"label", "l", ofilter, nil,
		`Show only flows related to an endpoint with the given labels (e.g. "key1=value1", "reserved:world")`))
	filterFlags.Var(filterVar(
		"to-label", ofilter,
		`Show only flows terminating in an endpoint with given labels (e.g. "key1=value1", "reserved:world")`))

	filterFlags.Var(filterVar(
		"from-service", ofilter,
		"Shows flows where the source IP address matches the ClusterIP address of the given service name prefix([namespace/]<svc-name>). If namespace is not provided, 'default' is used"))
	filterFlags.Var(filterVar(
		"service", ofilter,
		"Shows flows where either the source or destination IP address matches the ClusterIP address of the given service name prefix ([namespace/]<svc-name>). If namespace is not provided, 'default' is used. "))
	filterFlags.Var(filterVar(
		"to-service", ofilter,
		"Shows flows where the destination IP address matches the ClusterIP address of the given service name prefix ([namespace/]<svc-name>). If namespace is not provided, 'default' is used"))

	filterFlags.Var(filterVar(
		"from-port", ofilter,
		"Show only flows with the given source port (e.g. 8080)"))
	filterFlags.Var(filterVar(
		"port", ofilter,
		"Show only flows with given port in either source or destination (e.g. 8080)"))
	filterFlags.Var(filterVar(
		"to-port", ofilter,
		"Show only flows with the given destination port (e.g. 8080)"))

	filterFlags.Var(filterVar(
		"from-workload", ofilter,
		"Show all flows originating at an endpoint with the given workload"))
	filterFlags.Var(filterVar(
		"workload", ofilter,
		"Show all flows related to an endpoint with the given workload"))
	filterFlags.Var(filterVar(
		"to-workload", ofilter,
		"Show all flows terminating at an endpoint with the given workload"))

	filterFlags.Var(filterVar(
		"from-identity", ofilter,
		"Show all flows originating at an endpoint with the given security identity"))
	filterFlags.Var(filterVar(
		"identity", ofilter,
		"Show all flows related to an endpoint with the given security identity"))
	filterFlags.Var(filterVar(
		"to-identity", ofilter,
		"Show all flows terminating at an endpoint with the given security identity"))
	filterFlags.Var(filterVar(
		"traffic-direction", ofilter,
		"Show all flows in the given traffic direction (either ingress or egress)"))
	filterFlags.Var(filterVar(
		"cel-expression", ofilter,
		"Filter flows using the given CEL expression"))
	filterFlags.Var(filterVar(
		"interface", ofilter,
		"Show all flows observed at the given interface name (e.g. eth0)"))

	rawFilterFlags.StringArray(allowlistFlag, []string{}, "Specify allowlist as JSON encoded FlowFilters")
	rawFilterFlags.StringArray(denylistFlag, []string{}, "Specify denylist as JSON encoded FlowFilters")

	// formatting flags specific to flows
	flowsFormattingFlags.BoolVar(
		&formattingOpts.numeric,
		"numeric",
		false,
		"Display all information in numeric form",
	)
	flowsFormattingFlags.BoolVar(
		&formattingOpts.enableIPTranslation,
		"ip-translation",
		true,
		"Translate IP addresses to logical names such as pod name, FQDN, ...",
	)
	flowsFormattingFlags.StringVar(
		&formattingOpts.color,
		"color", "auto",
		"Colorize the output when the output format is one of 'compact' or 'dict'. The value is one of 'auto' (default), 'always' or 'never'",
	)

	// advanced completion for flags
	flowsCmd.RegisterFlagCompletionFunc("ip-version", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"none", "v4", "v6"}, cobra.ShellCompDirectiveDefault
	})
	flowsCmd.RegisterFlagCompletionFunc("type", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		var completions []string
		for _, ftype := range flowEventTypes {
			completions = append(completions, ftype)
			for _, subtype := range flowEventTypeSubtypes[ftype] {
				completions = append(completions, fmt.Sprintf("%s:%s", ftype, subtype))
			}
		}
		return completions, cobra.ShellCompDirectiveDefault
	})
	flowsCmd.RegisterFlagCompletionFunc("verdict", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return verdicts, cobra.ShellCompDirectiveDefault
	})
	flowsCmd.RegisterFlagCompletionFunc("protocol", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return protocols, cobra.ShellCompDirectiveDefault
	})
	flowsCmd.RegisterFlagCompletionFunc("http-status", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		httpStatus := []string{
			"100", "101", "102", "103",
			"200", "201", "202", "203", "204", "205", "206", "207", "208",
			"226",
			"300", "301", "302", "303", "304", "305", "307", "308",
			"400", "401", "402", "403", "404", "405", "406", "407", "408", "409",
			"410", "411", "412", "413", "414", "415", "416", "417", "418",
			"421", "422", "423", "424", "425", "426", "428", "429",
			"431",
			"451",
			"500", "501", "502", "503", "504", "505", "506", "507", "508",
			"510", "511",
		}
		return httpStatus, cobra.ShellCompDirectiveDefault
	})
	flowsCmd.RegisterFlagCompletionFunc("http-method", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{
			http.MethodConnect,
			http.MethodDelete,
			http.MethodGet,
			http.MethodHead,
			http.MethodOptions,
			http.MethodPatch,
			http.MethodPost,
			http.MethodPut,
			http.MethodTrace,
		}, cobra.ShellCompDirectiveDefault
	})
	flowsCmd.RegisterFlagCompletionFunc("identity", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return reservedIdentitiesNames(), cobra.ShellCompDirectiveDefault
	})
	flowsCmd.RegisterFlagCompletionFunc("to-identity", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return reservedIdentitiesNames(), cobra.ShellCompDirectiveDefault
	})
	flowsCmd.RegisterFlagCompletionFunc("from-identity", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return reservedIdentitiesNames(), cobra.ShellCompDirectiveDefault
	})
	flowsCmd.RegisterFlagCompletionFunc("traffic-direction", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"ingress", "egress"}, cobra.ShellCompDirectiveDefault
	})
	flowsCmd.RegisterFlagCompletionFunc("output", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{
			"compact",
			"dict",
			"json",
			"jsonpb",
			"table",
		}, cobra.ShellCompDirectiveDefault
	})
	flowsCmd.RegisterFlagCompletionFunc("color", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"auto", "always", "never"}, cobra.ShellCompDirectiveDefault
	})
	flowsCmd.RegisterFlagCompletionFunc("time-format", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return hubtime.FormatNames, cobra.ShellCompDirectiveDefault
	})

	for _, fs := range flagSets {
		flowsCmd.Flags().AddFlagSet(fs)
	}
	// default value for when the flag is on the command line without any options
	flowsCmd.Flags().Lookup("not").NoOptDefVal = "true"
	template.RegisterFlagSets(flowsCmd, flagSets...)
	return flowsCmd
}

func handleFlowArgs(writer io.Writer, ofilter *flowFilter, debug bool) (err error) {
	if ofilter.blacklisting {
		return errors.New("trailing --not found in the arguments")
	}

	// initialize the printer with any options that were passed in
	var opts = []hubprinter.Option{
		hubprinter.Writer(writer),
		hubprinter.WithTimeFormat(hubtime.FormatNameToLayout(formattingOpts.timeFormat)),
		hubprinter.WithColor(formattingOpts.color),
	}

	jsonOut := false
	switch formattingOpts.output {
	case "compact":
		opts = append(opts, hubprinter.Compact())
	case "dict":
		opts = append(opts, hubprinter.Dict())
	case "json", "JSON":
		if config.Compat.LegacyJSONOutput {
			opts = append(opts, hubprinter.JSONLegacy())
			break
		}
		fallthrough
	case "jsonpb":
		opts = append(opts, hubprinter.JSONPB())
		jsonOut = true
	case "tab", "table":
		if selectorOpts.follow {
			return fmt.Errorf("table output format is not compatible with follow mode")
		}
		opts = append(opts, hubprinter.Tab())
	default:
		return fmt.Errorf("invalid output format: %s", formattingOpts.output)
	}
	if !jsonOut {
		if len(experimentalOpts.fieldMask) > 0 {
			return fmt.Errorf("%s output format is not compatible with custom field mask", formattingOpts.output)
		}
		if experimentalOpts.useDefaultMasks {
			experimentalOpts.fieldMask = defaults.FieldMask
		}
	}

	if otherOpts.ignoreStderr {
		opts = append(opts, hubprinter.IgnoreStderr())
	}
	if formattingOpts.numeric {
		formattingOpts.enableIPTranslation = false
	}
	if formattingOpts.enableIPTranslation {
		opts = append(opts, hubprinter.WithIPTranslation())
	}
	if debug {
		opts = append(opts, hubprinter.WithDebug())
	}
	if formattingOpts.nodeName {
		opts = append(opts, hubprinter.WithNodeName())
	}
	if formattingOpts.policyNames {
		opts = append(opts, hubprinter.WithPolicyNames())
	}
	printer = hubprinter.New(opts...)
	return nil
}

func parseRawFilters(filters []string) ([]*flowpb.FlowFilter, error) {
	var results []*flowpb.FlowFilter
	for _, f := range filters {
		dec := json.NewDecoder(strings.NewReader(f))
		for {
			var result flowpb.FlowFilter
			if err := dec.Decode(&result); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("failed to decode '%v': %w", f, err)
			}
			results = append(results, &result)
		}
	}
	return results, nil
}

func getFlowsRequest(ofilter *flowFilter, allowlist []string, denylist []string) (*observerpb.GetFlowsRequest, error) {
	first := selectorOpts.first > 0
	last := selectorOpts.last > 0
	if first && last {
		return nil, fmt.Errorf("cannot set both --first and --last")
	}
	if first && selectorOpts.all {
		return nil, fmt.Errorf("cannot set both --first and --all")
	}
	if first && selectorOpts.follow {
		return nil, fmt.Errorf("cannot set both --first and --follow")
	}
	if last && selectorOpts.all {
		return nil, fmt.Errorf("cannot set both --last and --all")
	}

	// convert selectorOpts.since into a param for GetFlows
	var since, until *timestamppb.Timestamp
	if selectorOpts.since != "" {
		st, err := hubtime.FromString(selectorOpts.since)
		if err != nil {
			return nil, fmt.Errorf("failed to parse the since time: %w", err)
		}

		since = timestamppb.New(st)
		if err := since.CheckValid(); err != nil {
			return nil, fmt.Errorf("failed to convert `since` timestamp to proto: %w", err)
		}
	}
	// Set the until field if --until option is specified and --follow
	// is not specified. If --since is specified but --until is not, the server sets the
	// --until option to the current timestamp.
	if selectorOpts.until != "" && !selectorOpts.follow {
		ut, err := hubtime.FromString(selectorOpts.until)
		if err != nil {
			return nil, fmt.Errorf("failed to parse the until time: %w", err)
		}
		until = timestamppb.New(ut)
		if err := until.CheckValid(); err != nil {
			return nil, fmt.Errorf("failed to convert `until` timestamp to proto: %w", err)
		}
	}

	if since == nil && until == nil && !first {
		switch {
		case selectorOpts.all:
			// all is an alias for last=uint64_max
			selectorOpts.last = ^uint64(0)
		case selectorOpts.last == 0 && !selectorOpts.follow && otherOpts.inputFile == "":
			// no specific parameters were provided, just a vanilla
			// `hubble observe` in non-follow mode
			selectorOpts.last = defaults.FlowPrintCount
		}
	}

	var (
		wl []*flowpb.FlowFilter
		bl []*flowpb.FlowFilter
	)
	if ofilter.whitelist != nil {
		wl = ofilter.whitelist.flowFilters()
	}
	if ofilter.blacklist != nil {
		bl = ofilter.blacklist.flowFilters()
	}

	// load filters from raw filter flags
	al, err := parseRawFilters(allowlist)
	if err != nil {
		return nil, fmt.Errorf("invalid --allowlist flag: %w", err)

	}
	wl = append(wl, al...)
	dl, err := parseRawFilters(denylist)
	if err != nil {
		return nil, fmt.Errorf("invalid --denylist flag: %w", err)
	}
	bl = append(bl, dl...)

	number := selectorOpts.last
	if first {
		number = selectorOpts.first
	}

	req := &observerpb.GetFlowsRequest{
		Number:    number,
		Follow:    selectorOpts.follow,
		Whitelist: wl,
		Blacklist: bl,
		Since:     since,
		Until:     until,
		First:     first,
	}

	if len(experimentalOpts.fieldMask) > 0 {
		fm, err := fieldmaskpb.New(&flowpb.Flow{}, experimentalOpts.fieldMask...)
		if err != nil {
			return nil, fmt.Errorf("failed to construct field mask: %w", err)
		}
		req.Experimental = &observerpb.GetFlowsRequest_Experimental{
			FieldMask: fm,
		}
	}

	return req, nil
}

func getFlows(ctx context.Context, client observerpb.ObserverClient, req *observerpb.GetFlowsRequest) error {
	b, err := client.GetFlows(ctx, req)
	if err != nil {
		return err
	}
	defer printer.Close()

	for {
		getFlowResponse, err := b.Recv()
		switch {
		case errors.Is(err, io.EOF), errors.Is(err, context.Canceled):
			return nil
		case err == nil:
		default:
			if status.Code(err) == codes.Canceled {
				return nil
			}
			return err
		}

		if err = printer.WriteGetFlowsResponse(getFlowResponse); err != nil {
			return err
		}
	}
}
