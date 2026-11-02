// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package cell

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/hubble/parser"
	parserOptions "github.com/cilium/cilium/pkg/hubble/parser/options"
	resolverTypes "github.com/cilium/cilium/pkg/hubble/resolver/types"
)

var Cell = cell.Module(
	"payload-parser",
	"Provides a payload parser for Hubble",

	cell.Provide(newPayloadParser),
	cell.Config(defaultConfig),
)

func newPayloadParser(params payloadParserParams) (parser.Decoder, error) {
	if err := params.Config.validate(); err != nil {
		return nil, fmt.Errorf("failed to validate configuration: %w", err)
	}
	var parserOpts []parserOptions.Option
	if params.Config.EnableRedact {
		parserOpts = append(
			parserOpts,
			parserOptions.WithRedact(
				params.Config.RedactHttpURLQuery,
				params.Config.RedactHttpUserInfo,
				params.Config.RedactHttpHeadersAllow,
				params.Config.RedactHttpHeadersDeny,
			),
		)
	}
	parserOpts = append(
		parserOpts,
		parserOptions.WithNetworkPolicyCorrelation(
			params.Config.EnableNetworkPolicyCorrelation,
		))
	parserOpts = append(
		parserOpts,
		parserOptions.WithSkipUnknownCGroupIDs(
			params.Config.SkipUnknownCGroupIDs,
		),
	)
	parserOpts = append(
		parserOpts,
		params.ParserOptions...,
	)
	return parser.New(params.Log, params.EndpointGetter, params.IdentityGetter, params.DnsGetter, params.IPGetter, params.ServiceGetter, params.LinkGetter, params.CGroupGetter, parserOpts...)
}

type payloadParserParams struct {
	cell.In

	Log *slog.Logger

	ServiceGetter  resolverTypes.ServiceGetter
	EndpointGetter resolverTypes.EndpointGetter
	IdentityGetter resolverTypes.IdentityGetter
	IPGetter       resolverTypes.IPGetter
	DnsGetter      resolverTypes.DNSGetter
	LinkGetter     resolverTypes.LinkGetter
	CGroupGetter   resolverTypes.PodMetadataGetter

	Config config
	// NOTE: ordering is not guaranteed, do not rely on it.
	ParserOptions []parserOptions.Option `group:"hubble-parser-options"`
}
