Generated from https://github.com/Azure/azure-rest-api-specs/tree/3c764635e7d442b3e74caf593029fcd440b3ef82/specification/network/resource-manager/readme.md tag: `package-2019-09`

Code generator @microsoft.azure/autorest.go@2.1.168

## Breaking Changes

### Removed Funcs

1. *ApplicationGatewaysBackendHealthFuture.Result(ApplicationGatewaysClient) (ApplicationGatewayBackendHealth, error)
1. *ApplicationGatewaysBackendHealthOnDemandFuture.Result(ApplicationGatewaysClient) (ApplicationGatewayBackendHealthOnDemand, error)
1. *ApplicationGatewaysCreateOrUpdateFuture.Result(ApplicationGatewaysClient) (ApplicationGateway, error)
1. *ApplicationGatewaysDeleteFuture.Result(ApplicationGatewaysClient) (autorest.Response, error)
1. *ApplicationGatewaysStartFuture.Result(ApplicationGatewaysClient) (autorest.Response, error)
1. *ApplicationGatewaysStopFuture.Result(ApplicationGatewaysClient) (autorest.Response, error)
1. *ApplicationSecurityGroupsCreateOrUpdateFuture.Result(ApplicationSecurityGroupsClient) (ApplicationSecurityGroup, error)
1. *ApplicationSecurityGroupsDeleteFuture.Result(ApplicationSecurityGroupsClient) (autorest.Response, error)
1. *AzureFirewallsCreateOrUpdateFuture.Result(AzureFirewallsClient) (AzureFirewall, error)
1. *AzureFirewallsDeleteFuture.Result(AzureFirewallsClient) (autorest.Response, error)
1. *AzureFirewallsUpdateTagsFuture.Result(AzureFirewallsClient) (AzureFirewall, error)
1. *BastionHostsCreateOrUpdateFuture.Result(BastionHostsClient) (BastionHost, error)
1. *BastionHostsDeleteFuture.Result(BastionHostsClient) (autorest.Response, error)
1. *ConnectionMonitorsCreateOrUpdateFuture.Result(ConnectionMonitorsClient) (ConnectionMonitorResult, error)
1. *ConnectionMonitorsDeleteFuture.Result(ConnectionMonitorsClient) (autorest.Response, error)
1. *ConnectionMonitorsQueryFuture.Result(ConnectionMonitorsClient) (ConnectionMonitorQueryResult, error)
1. *ConnectionMonitorsStartFuture.Result(ConnectionMonitorsClient) (autorest.Response, error)
1. *ConnectionMonitorsStopFuture.Result(ConnectionMonitorsClient) (autorest.Response, error)
1. *DdosCustomPoliciesCreateOrUpdateFuture.Result(DdosCustomPoliciesClient) (DdosCustomPolicy, error)
1. *DdosCustomPoliciesDeleteFuture.Result(DdosCustomPoliciesClient) (autorest.Response, error)
1. *DdosProtectionPlansCreateOrUpdateFuture.Result(DdosProtectionPlansClient) (DdosProtectionPlan, error)
1. *DdosProtectionPlansDeleteFuture.Result(DdosProtectionPlansClient) (autorest.Response, error)
1. *DeleteBastionShareableLinkFuture.Result(BaseClient) (autorest.Response, error)
1. *ExpressRouteCircuitAuthorizationsCreateOrUpdateFuture.Result(ExpressRouteCircuitAuthorizationsClient) (ExpressRouteCircuitAuthorization, error)
1. *ExpressRouteCircuitAuthorizationsDeleteFuture.Result(ExpressRouteCircuitAuthorizationsClient) (autorest.Response, error)
1. *ExpressRouteCircuitConnectionsCreateOrUpdateFuture.Result(ExpressRouteCircuitConnectionsClient) (ExpressRouteCircuitConnection, error)
1. *ExpressRouteCircuitConnectionsDeleteFuture.Result(ExpressRouteCircuitConnectionsClient) (autorest.Response, error)
1. *ExpressRouteCircuitPeeringsCreateOrUpdateFuture.Result(ExpressRouteCircuitPeeringsClient) (ExpressRouteCircuitPeering, error)
1. *ExpressRouteCircuitPeeringsDeleteFuture.Result(ExpressRouteCircuitPeeringsClient) (autorest.Response, error)
1. *ExpressRouteCircuitsCreateOrUpdateFuture.Result(ExpressRouteCircuitsClient) (ExpressRouteCircuit, error)
1. *ExpressRouteCircuitsDeleteFuture.Result(ExpressRouteCircuitsClient) (autorest.Response, error)
1. *ExpressRouteCircuitsListArpTableFuture.Result(ExpressRouteCircuitsClient) (ExpressRouteCircuitsArpTableListResult, error)
1. *ExpressRouteCircuitsListRoutesTableFuture.Result(ExpressRouteCircuitsClient) (ExpressRouteCircuitsRoutesTableListResult, error)
1. *ExpressRouteCircuitsListRoutesTableSummaryFuture.Result(ExpressRouteCircuitsClient) (ExpressRouteCircuitsRoutesTableSummaryListResult, error)
1. *ExpressRouteConnectionsCreateOrUpdateFuture.Result(ExpressRouteConnectionsClient) (ExpressRouteConnection, error)
1. *ExpressRouteConnectionsDeleteFuture.Result(ExpressRouteConnectionsClient) (autorest.Response, error)
1. *ExpressRouteCrossConnectionPeeringsCreateOrUpdateFuture.Result(ExpressRouteCrossConnectionPeeringsClient) (ExpressRouteCrossConnectionPeering, error)
1. *ExpressRouteCrossConnectionPeeringsDeleteFuture.Result(ExpressRouteCrossConnectionPeeringsClient) (autorest.Response, error)
1. *ExpressRouteCrossConnectionsCreateOrUpdateFuture.Result(ExpressRouteCrossConnectionsClient) (ExpressRouteCrossConnection, error)
1. *ExpressRouteCrossConnectionsListArpTableFuture.Result(ExpressRouteCrossConnectionsClient) (ExpressRouteCircuitsArpTableListResult, error)
1. *ExpressRouteCrossConnectionsListRoutesTableFuture.Result(ExpressRouteCrossConnectionsClient) (ExpressRouteCircuitsRoutesTableListResult, error)
1. *ExpressRouteCrossConnectionsListRoutesTableSummaryFuture.Result(ExpressRouteCrossConnectionsClient) (ExpressRouteCrossConnectionsRoutesTableSummaryListResult, error)
1. *ExpressRouteGatewaysCreateOrUpdateFuture.Result(ExpressRouteGatewaysClient) (ExpressRouteGateway, error)
1. *ExpressRouteGatewaysDeleteFuture.Result(ExpressRouteGatewaysClient) (autorest.Response, error)
1. *ExpressRoutePortsCreateOrUpdateFuture.Result(ExpressRoutePortsClient) (ExpressRoutePort, error)
1. *ExpressRoutePortsDeleteFuture.Result(ExpressRoutePortsClient) (autorest.Response, error)
1. *FirewallPoliciesCreateOrUpdateFuture.Result(FirewallPoliciesClient) (FirewallPolicy, error)
1. *FirewallPoliciesDeleteFuture.Result(FirewallPoliciesClient) (autorest.Response, error)
1. *FirewallPolicyRuleGroupsCreateOrUpdateFuture.Result(FirewallPolicyRuleGroupsClient) (FirewallPolicyRuleGroup, error)
1. *FirewallPolicyRuleGroupsDeleteFuture.Result(FirewallPolicyRuleGroupsClient) (autorest.Response, error)
1. *GeneratevirtualwanvpnserverconfigurationvpnprofileFuture.Result(BaseClient) (VpnProfileResponse, error)
1. *GetActiveSessionsAllFuture.Result(BaseClient) (BastionActiveSessionListResultPage, error)
1. *GetActiveSessionsFuture.Result(BaseClient) (BastionActiveSessionListResultPage, error)
1. *IPGroupsCreateOrUpdateFuture.Result(IPGroupsClient) (IPGroup, error)
1. *IPGroupsDeleteFuture.Result(IPGroupsClient) (autorest.Response, error)
1. *InboundNatRulesCreateOrUpdateFuture.Result(InboundNatRulesClient) (InboundNatRule, error)
1. *InboundNatRulesDeleteFuture.Result(InboundNatRulesClient) (autorest.Response, error)
1. *InterfaceTapConfigurationsCreateOrUpdateFuture.Result(InterfaceTapConfigurationsClient) (InterfaceTapConfiguration, error)
1. *InterfaceTapConfigurationsDeleteFuture.Result(InterfaceTapConfigurationsClient) (autorest.Response, error)
1. *InterfacesCreateOrUpdateFuture.Result(InterfacesClient) (Interface, error)
1. *InterfacesDeleteFuture.Result(InterfacesClient) (autorest.Response, error)
1. *InterfacesGetEffectiveRouteTableFuture.Result(InterfacesClient) (EffectiveRouteListResult, error)
1. *InterfacesListEffectiveNetworkSecurityGroupsFuture.Result(InterfacesClient) (EffectiveNetworkSecurityGroupListResult, error)
1. *LoadBalancersCreateOrUpdateFuture.Result(LoadBalancersClient) (LoadBalancer, error)
1. *LoadBalancersDeleteFuture.Result(LoadBalancersClient) (autorest.Response, error)
1. *LocalNetworkGatewaysCreateOrUpdateFuture.Result(LocalNetworkGatewaysClient) (LocalNetworkGateway, error)
1. *LocalNetworkGatewaysDeleteFuture.Result(LocalNetworkGatewaysClient) (autorest.Response, error)
1. *NatGatewaysCreateOrUpdateFuture.Result(NatGatewaysClient) (NatGateway, error)
1. *NatGatewaysDeleteFuture.Result(NatGatewaysClient) (autorest.Response, error)
1. *P2sVpnGatewaysCreateOrUpdateFuture.Result(P2sVpnGatewaysClient) (P2SVpnGateway, error)
1. *P2sVpnGatewaysDeleteFuture.Result(P2sVpnGatewaysClient) (autorest.Response, error)
1. *P2sVpnGatewaysGenerateVpnProfileFuture.Result(P2sVpnGatewaysClient) (VpnProfileResponse, error)
1. *P2sVpnGatewaysGetP2sVpnConnectionHealthDetailedFuture.Result(P2sVpnGatewaysClient) (P2SVpnConnectionHealth, error)
1. *P2sVpnGatewaysGetP2sVpnConnectionHealthFuture.Result(P2sVpnGatewaysClient) (P2SVpnGateway, error)
1. *PacketCapturesCreateFuture.Result(PacketCapturesClient) (PacketCaptureResult, error)
1. *PacketCapturesDeleteFuture.Result(PacketCapturesClient) (autorest.Response, error)
1. *PacketCapturesGetStatusFuture.Result(PacketCapturesClient) (PacketCaptureQueryStatusResult, error)
1. *PacketCapturesStopFuture.Result(PacketCapturesClient) (autorest.Response, error)
1. *PrivateEndpointsCreateOrUpdateFuture.Result(PrivateEndpointsClient) (PrivateEndpoint, error)
1. *PrivateEndpointsDeleteFuture.Result(PrivateEndpointsClient) (autorest.Response, error)
1. *PrivateLinkServicesCheckPrivateLinkServiceVisibilityByResourceGroupFuture.Result(PrivateLinkServicesClient) (PrivateLinkServiceVisibility, error)
1. *PrivateLinkServicesCheckPrivateLinkServiceVisibilityFuture.Result(PrivateLinkServicesClient) (PrivateLinkServiceVisibility, error)
1. *PrivateLinkServicesCreateOrUpdateFuture.Result(PrivateLinkServicesClient) (PrivateLinkService, error)
1. *PrivateLinkServicesDeleteFuture.Result(PrivateLinkServicesClient) (autorest.Response, error)
1. *PrivateLinkServicesDeletePrivateEndpointConnectionFuture.Result(PrivateLinkServicesClient) (autorest.Response, error)
1. *ProfilesDeleteFuture.Result(ProfilesClient) (autorest.Response, error)
1. *PublicIPAddressesCreateOrUpdateFuture.Result(PublicIPAddressesClient) (PublicIPAddress, error)
1. *PublicIPAddressesDeleteFuture.Result(PublicIPAddressesClient) (autorest.Response, error)
1. *PublicIPPrefixesCreateOrUpdateFuture.Result(PublicIPPrefixesClient) (PublicIPPrefix, error)
1. *PublicIPPrefixesDeleteFuture.Result(PublicIPPrefixesClient) (autorest.Response, error)
1. *PutBastionShareableLinkAllFuture.Result(BaseClient) (BastionShareableLinkListResultPage, error)
1. *PutBastionShareableLinkFuture.Result(BaseClient) (BastionShareableLinkListResultPage, error)
1. *RouteFilterRulesCreateOrUpdateFuture.Result(RouteFilterRulesClient) (RouteFilterRule, error)
1. *RouteFilterRulesDeleteFuture.Result(RouteFilterRulesClient) (autorest.Response, error)
1. *RouteFiltersCreateOrUpdateFuture.Result(RouteFiltersClient) (RouteFilter, error)
1. *RouteFiltersDeleteFuture.Result(RouteFiltersClient) (autorest.Response, error)
1. *RouteTablesCreateOrUpdateFuture.Result(RouteTablesClient) (RouteTable, error)
1. *RouteTablesDeleteFuture.Result(RouteTablesClient) (autorest.Response, error)
1. *RoutesCreateOrUpdateFuture.Result(RoutesClient) (Route, error)
1. *RoutesDeleteFuture.Result(RoutesClient) (autorest.Response, error)
1. *SecurityGroupsCreateOrUpdateFuture.Result(SecurityGroupsClient) (SecurityGroup, error)
1. *SecurityGroupsDeleteFuture.Result(SecurityGroupsClient) (autorest.Response, error)
1. *SecurityRulesCreateOrUpdateFuture.Result(SecurityRulesClient) (SecurityRule, error)
1. *SecurityRulesDeleteFuture.Result(SecurityRulesClient) (autorest.Response, error)
1. *ServiceEndpointPoliciesCreateOrUpdateFuture.Result(ServiceEndpointPoliciesClient) (ServiceEndpointPolicy, error)
1. *ServiceEndpointPoliciesDeleteFuture.Result(ServiceEndpointPoliciesClient) (autorest.Response, error)
1. *ServiceEndpointPolicyDefinitionsCreateOrUpdateFuture.Result(ServiceEndpointPolicyDefinitionsClient) (ServiceEndpointPolicyDefinition, error)
1. *ServiceEndpointPolicyDefinitionsDeleteFuture.Result(ServiceEndpointPolicyDefinitionsClient) (autorest.Response, error)
1. *SubnetsCreateOrUpdateFuture.Result(SubnetsClient) (Subnet, error)
1. *SubnetsDeleteFuture.Result(SubnetsClient) (autorest.Response, error)
1. *SubnetsPrepareNetworkPoliciesFuture.Result(SubnetsClient) (autorest.Response, error)
1. *SubnetsUnprepareNetworkPoliciesFuture.Result(SubnetsClient) (autorest.Response, error)
1. *VirtualHubRouteTableV2sCreateOrUpdateFuture.Result(VirtualHubRouteTableV2sClient) (VirtualHubRouteTableV2, error)
1. *VirtualHubRouteTableV2sDeleteFuture.Result(VirtualHubRouteTableV2sClient) (autorest.Response, error)
1. *VirtualHubsCreateOrUpdateFuture.Result(VirtualHubsClient) (VirtualHub, error)
1. *VirtualHubsDeleteFuture.Result(VirtualHubsClient) (autorest.Response, error)
1. *VirtualNetworkGatewayConnectionsCreateOrUpdateFuture.Result(VirtualNetworkGatewayConnectionsClient) (VirtualNetworkGatewayConnection, error)
1. *VirtualNetworkGatewayConnectionsDeleteFuture.Result(VirtualNetworkGatewayConnectionsClient) (autorest.Response, error)
1. *VirtualNetworkGatewayConnectionsResetSharedKeyFuture.Result(VirtualNetworkGatewayConnectionsClient) (ConnectionResetSharedKey, error)
1. *VirtualNetworkGatewayConnectionsSetSharedKeyFuture.Result(VirtualNetworkGatewayConnectionsClient) (ConnectionSharedKey, error)
1. *VirtualNetworkGatewayConnectionsStartPacketCaptureFuture.Result(VirtualNetworkGatewayConnectionsClient) (String, error)
1. *VirtualNetworkGatewayConnectionsStopPacketCaptureFuture.Result(VirtualNetworkGatewayConnectionsClient) (String, error)
1. *VirtualNetworkGatewayConnectionsUpdateTagsFuture.Result(VirtualNetworkGatewayConnectionsClient) (VirtualNetworkGatewayConnection, error)
1. *VirtualNetworkGatewaysCreateOrUpdateFuture.Result(VirtualNetworkGatewaysClient) (VirtualNetworkGateway, error)
1. *VirtualNetworkGatewaysDeleteFuture.Result(VirtualNetworkGatewaysClient) (autorest.Response, error)
1. *VirtualNetworkGatewaysGenerateVpnProfileFuture.Result(VirtualNetworkGatewaysClient) (String, error)
1. *VirtualNetworkGatewaysGeneratevpnclientpackageFuture.Result(VirtualNetworkGatewaysClient) (String, error)
1. *VirtualNetworkGatewaysGetAdvertisedRoutesFuture.Result(VirtualNetworkGatewaysClient) (GatewayRouteListResult, error)
1. *VirtualNetworkGatewaysGetBgpPeerStatusFuture.Result(VirtualNetworkGatewaysClient) (BgpPeerStatusListResult, error)
1. *VirtualNetworkGatewaysGetLearnedRoutesFuture.Result(VirtualNetworkGatewaysClient) (GatewayRouteListResult, error)
1. *VirtualNetworkGatewaysGetVpnProfilePackageURLFuture.Result(VirtualNetworkGatewaysClient) (String, error)
1. *VirtualNetworkGatewaysGetVpnclientConnectionHealthFuture.Result(VirtualNetworkGatewaysClient) (VpnClientConnectionHealthDetailListResult, error)
1. *VirtualNetworkGatewaysGetVpnclientIpsecParametersFuture.Result(VirtualNetworkGatewaysClient) (VpnClientIPsecParameters, error)
1. *VirtualNetworkGatewaysResetFuture.Result(VirtualNetworkGatewaysClient) (VirtualNetworkGateway, error)
1. *VirtualNetworkGatewaysResetVpnClientSharedKeyFuture.Result(VirtualNetworkGatewaysClient) (autorest.Response, error)
1. *VirtualNetworkGatewaysSetVpnclientIpsecParametersFuture.Result(VirtualNetworkGatewaysClient) (VpnClientIPsecParameters, error)
1. *VirtualNetworkGatewaysStartPacketCaptureFuture.Result(VirtualNetworkGatewaysClient) (String, error)
1. *VirtualNetworkGatewaysStopPacketCaptureFuture.Result(VirtualNetworkGatewaysClient) (String, error)
1. *VirtualNetworkGatewaysUpdateTagsFuture.Result(VirtualNetworkGatewaysClient) (VirtualNetworkGateway, error)
1. *VirtualNetworkPeeringsCreateOrUpdateFuture.Result(VirtualNetworkPeeringsClient) (VirtualNetworkPeering, error)
1. *VirtualNetworkPeeringsDeleteFuture.Result(VirtualNetworkPeeringsClient) (autorest.Response, error)
1. *VirtualNetworkTapsCreateOrUpdateFuture.Result(VirtualNetworkTapsClient) (VirtualNetworkTap, error)
1. *VirtualNetworkTapsDeleteFuture.Result(VirtualNetworkTapsClient) (autorest.Response, error)
1. *VirtualNetworksCreateOrUpdateFuture.Result(VirtualNetworksClient) (VirtualNetwork, error)
1. *VirtualNetworksDeleteFuture.Result(VirtualNetworksClient) (autorest.Response, error)
1. *VirtualRouterPeeringsCreateOrUpdateFuture.Result(VirtualRouterPeeringsClient) (VirtualRouterPeering, error)
1. *VirtualRouterPeeringsDeleteFuture.Result(VirtualRouterPeeringsClient) (autorest.Response, error)
1. *VirtualRoutersCreateOrUpdateFuture.Result(VirtualRoutersClient) (VirtualRouter, error)
1. *VirtualRoutersDeleteFuture.Result(VirtualRoutersClient) (autorest.Response, error)
1. *VirtualWansCreateOrUpdateFuture.Result(VirtualWansClient) (VirtualWAN, error)
1. *VirtualWansDeleteFuture.Result(VirtualWansClient) (autorest.Response, error)
1. *VpnConnectionsCreateOrUpdateFuture.Result(VpnConnectionsClient) (VpnConnection, error)
1. *VpnConnectionsDeleteFuture.Result(VpnConnectionsClient) (autorest.Response, error)
1. *VpnGatewaysCreateOrUpdateFuture.Result(VpnGatewaysClient) (VpnGateway, error)
1. *VpnGatewaysDeleteFuture.Result(VpnGatewaysClient) (autorest.Response, error)
1. *VpnGatewaysResetFuture.Result(VpnGatewaysClient) (VpnGateway, error)
1. *VpnServerConfigurationsAssociatedWithVirtualWanListFuture.Result(VpnServerConfigurationsAssociatedWithVirtualWanClient) (VpnServerConfigurationsResponse, error)
1. *VpnServerConfigurationsCreateOrUpdateFuture.Result(VpnServerConfigurationsClient) (VpnServerConfiguration, error)
1. *VpnServerConfigurationsDeleteFuture.Result(VpnServerConfigurationsClient) (autorest.Response, error)
1. *VpnSitesConfigurationDownloadFuture.Result(VpnSitesConfigurationClient) (autorest.Response, error)
1. *VpnSitesCreateOrUpdateFuture.Result(VpnSitesClient) (VpnSite, error)
1. *VpnSitesDeleteFuture.Result(VpnSitesClient) (autorest.Response, error)
1. *WatchersCheckConnectivityFuture.Result(WatchersClient) (ConnectivityInformation, error)
1. *WatchersDeleteFuture.Result(WatchersClient) (autorest.Response, error)
1. *WatchersGetAzureReachabilityReportFuture.Result(WatchersClient) (AzureReachabilityReport, error)
1. *WatchersGetFlowLogStatusFuture.Result(WatchersClient) (FlowLogInformation, error)
1. *WatchersGetNetworkConfigurationDiagnosticFuture.Result(WatchersClient) (ConfigurationDiagnosticResponse, error)
1. *WatchersGetNextHopFuture.Result(WatchersClient) (NextHopResult, error)
1. *WatchersGetTroubleshootingFuture.Result(WatchersClient) (TroubleshootingResult, error)
1. *WatchersGetTroubleshootingResultFuture.Result(WatchersClient) (TroubleshootingResult, error)
1. *WatchersGetVMSecurityRulesFuture.Result(WatchersClient) (SecurityGroupViewResult, error)
1. *WatchersListAvailableProvidersFuture.Result(WatchersClient) (AvailableProvidersList, error)
1. *WatchersSetFlowLogConfigurationFuture.Result(WatchersClient) (FlowLogInformation, error)
1. *WatchersVerifyIPFlowFuture.Result(WatchersClient) (VerificationIPFlowResult, error)
1. *WebApplicationFirewallPoliciesDeleteFuture.Result(WebApplicationFirewallPoliciesClient) (autorest.Response, error)

## Struct Changes

### Removed Struct Fields

1. ApplicationGatewaysBackendHealthFuture.azure.Future
1. ApplicationGatewaysBackendHealthOnDemandFuture.azure.Future
1. ApplicationGatewaysCreateOrUpdateFuture.azure.Future
1. ApplicationGatewaysDeleteFuture.azure.Future
1. ApplicationGatewaysStartFuture.azure.Future
1. ApplicationGatewaysStopFuture.azure.Future
1. ApplicationSecurityGroupsCreateOrUpdateFuture.azure.Future
1. ApplicationSecurityGroupsDeleteFuture.azure.Future
1. AzureFirewallsCreateOrUpdateFuture.azure.Future
1. AzureFirewallsDeleteFuture.azure.Future
1. AzureFirewallsUpdateTagsFuture.azure.Future
1. BastionHostsCreateOrUpdateFuture.azure.Future
1. BastionHostsDeleteFuture.azure.Future
1. ConnectionMonitorsCreateOrUpdateFuture.azure.Future
1. ConnectionMonitorsDeleteFuture.azure.Future
1. ConnectionMonitorsQueryFuture.azure.Future
1. ConnectionMonitorsStartFuture.azure.Future
1. ConnectionMonitorsStopFuture.azure.Future
1. DdosCustomPoliciesCreateOrUpdateFuture.azure.Future
1. DdosCustomPoliciesDeleteFuture.azure.Future
1. DdosProtectionPlansCreateOrUpdateFuture.azure.Future
1. DdosProtectionPlansDeleteFuture.azure.Future
1. DeleteBastionShareableLinkFuture.azure.Future
1. ExpressRouteCircuitAuthorizationsCreateOrUpdateFuture.azure.Future
1. ExpressRouteCircuitAuthorizationsDeleteFuture.azure.Future
1. ExpressRouteCircuitConnectionsCreateOrUpdateFuture.azure.Future
1. ExpressRouteCircuitConnectionsDeleteFuture.azure.Future
1. ExpressRouteCircuitPeeringsCreateOrUpdateFuture.azure.Future
1. ExpressRouteCircuitPeeringsDeleteFuture.azure.Future
1. ExpressRouteCircuitsCreateOrUpdateFuture.azure.Future
1. ExpressRouteCircuitsDeleteFuture.azure.Future
1. ExpressRouteCircuitsListArpTableFuture.azure.Future
1. ExpressRouteCircuitsListRoutesTableFuture.azure.Future
1. ExpressRouteCircuitsListRoutesTableSummaryFuture.azure.Future
1. ExpressRouteConnectionsCreateOrUpdateFuture.azure.Future
1. ExpressRouteConnectionsDeleteFuture.azure.Future
1. ExpressRouteCrossConnectionPeeringsCreateOrUpdateFuture.azure.Future
1. ExpressRouteCrossConnectionPeeringsDeleteFuture.azure.Future
1. ExpressRouteCrossConnectionsCreateOrUpdateFuture.azure.Future
1. ExpressRouteCrossConnectionsListArpTableFuture.azure.Future
1. ExpressRouteCrossConnectionsListRoutesTableFuture.azure.Future
1. ExpressRouteCrossConnectionsListRoutesTableSummaryFuture.azure.Future
1. ExpressRouteGatewaysCreateOrUpdateFuture.azure.Future
1. ExpressRouteGatewaysDeleteFuture.azure.Future
1. ExpressRoutePortsCreateOrUpdateFuture.azure.Future
1. ExpressRoutePortsDeleteFuture.azure.Future
1. FirewallPoliciesCreateOrUpdateFuture.azure.Future
1. FirewallPoliciesDeleteFuture.azure.Future
1. FirewallPolicyRuleGroupsCreateOrUpdateFuture.azure.Future
1. FirewallPolicyRuleGroupsDeleteFuture.azure.Future
1. GeneratevirtualwanvpnserverconfigurationvpnprofileFuture.azure.Future
1. GetActiveSessionsAllFuture.azure.Future
1. GetActiveSessionsFuture.azure.Future
1. IPGroupsCreateOrUpdateFuture.azure.Future
1. IPGroupsDeleteFuture.azure.Future
1. InboundNatRulesCreateOrUpdateFuture.azure.Future
1. InboundNatRulesDeleteFuture.azure.Future
1. InterfaceTapConfigurationsCreateOrUpdateFuture.azure.Future
1. InterfaceTapConfigurationsDeleteFuture.azure.Future
1. InterfacesCreateOrUpdateFuture.azure.Future
1. InterfacesDeleteFuture.azure.Future
1. InterfacesGetEffectiveRouteTableFuture.azure.Future
1. InterfacesListEffectiveNetworkSecurityGroupsFuture.azure.Future
1. LoadBalancersCreateOrUpdateFuture.azure.Future
1. LoadBalancersDeleteFuture.azure.Future
1. LocalNetworkGatewaysCreateOrUpdateFuture.azure.Future
1. LocalNetworkGatewaysDeleteFuture.azure.Future
1. NatGatewaysCreateOrUpdateFuture.azure.Future
1. NatGatewaysDeleteFuture.azure.Future
1. P2sVpnGatewaysCreateOrUpdateFuture.azure.Future
1. P2sVpnGatewaysDeleteFuture.azure.Future
1. P2sVpnGatewaysGenerateVpnProfileFuture.azure.Future
1. P2sVpnGatewaysGetP2sVpnConnectionHealthDetailedFuture.azure.Future
1. P2sVpnGatewaysGetP2sVpnConnectionHealthFuture.azure.Future
1. PacketCapturesCreateFuture.azure.Future
1. PacketCapturesDeleteFuture.azure.Future
1. PacketCapturesGetStatusFuture.azure.Future
1. PacketCapturesStopFuture.azure.Future
1. PrivateEndpointsCreateOrUpdateFuture.azure.Future
1. PrivateEndpointsDeleteFuture.azure.Future
1. PrivateLinkServicesCheckPrivateLinkServiceVisibilityByResourceGroupFuture.azure.Future
1. PrivateLinkServicesCheckPrivateLinkServiceVisibilityFuture.azure.Future
1. PrivateLinkServicesCreateOrUpdateFuture.azure.Future
1. PrivateLinkServicesDeleteFuture.azure.Future
1. PrivateLinkServicesDeletePrivateEndpointConnectionFuture.azure.Future
1. ProfilesDeleteFuture.azure.Future
1. PublicIPAddressesCreateOrUpdateFuture.azure.Future
1. PublicIPAddressesDeleteFuture.azure.Future
1. PublicIPPrefixesCreateOrUpdateFuture.azure.Future
1. PublicIPPrefixesDeleteFuture.azure.Future
1. PutBastionShareableLinkAllFuture.azure.Future
1. PutBastionShareableLinkFuture.azure.Future
1. RouteFilterRulesCreateOrUpdateFuture.azure.Future
1. RouteFilterRulesDeleteFuture.azure.Future
1. RouteFiltersCreateOrUpdateFuture.azure.Future
1. RouteFiltersDeleteFuture.azure.Future
1. RouteTablesCreateOrUpdateFuture.azure.Future
1. RouteTablesDeleteFuture.azure.Future
1. RoutesCreateOrUpdateFuture.azure.Future
1. RoutesDeleteFuture.azure.Future
1. SecurityGroupsCreateOrUpdateFuture.azure.Future
1. SecurityGroupsDeleteFuture.azure.Future
1. SecurityRulesCreateOrUpdateFuture.azure.Future
1. SecurityRulesDeleteFuture.azure.Future
1. ServiceEndpointPoliciesCreateOrUpdateFuture.azure.Future
1. ServiceEndpointPoliciesDeleteFuture.azure.Future
1. ServiceEndpointPolicyDefinitionsCreateOrUpdateFuture.azure.Future
1. ServiceEndpointPolicyDefinitionsDeleteFuture.azure.Future
1. SubnetsCreateOrUpdateFuture.azure.Future
1. SubnetsDeleteFuture.azure.Future
1. SubnetsPrepareNetworkPoliciesFuture.azure.Future
1. SubnetsUnprepareNetworkPoliciesFuture.azure.Future
1. VirtualHubRouteTableV2sCreateOrUpdateFuture.azure.Future
1. VirtualHubRouteTableV2sDeleteFuture.azure.Future
1. VirtualHubsCreateOrUpdateFuture.azure.Future
1. VirtualHubsDeleteFuture.azure.Future
1. VirtualNetworkGatewayConnectionsCreateOrUpdateFuture.azure.Future
1. VirtualNetworkGatewayConnectionsDeleteFuture.azure.Future
1. VirtualNetworkGatewayConnectionsResetSharedKeyFuture.azure.Future
1. VirtualNetworkGatewayConnectionsSetSharedKeyFuture.azure.Future
1. VirtualNetworkGatewayConnectionsStartPacketCaptureFuture.azure.Future
1. VirtualNetworkGatewayConnectionsStopPacketCaptureFuture.azure.Future
1. VirtualNetworkGatewayConnectionsUpdateTagsFuture.azure.Future
1. VirtualNetworkGatewaysCreateOrUpdateFuture.azure.Future
1. VirtualNetworkGatewaysDeleteFuture.azure.Future
1. VirtualNetworkGatewaysGenerateVpnProfileFuture.azure.Future
1. VirtualNetworkGatewaysGeneratevpnclientpackageFuture.azure.Future
1. VirtualNetworkGatewaysGetAdvertisedRoutesFuture.azure.Future
1. VirtualNetworkGatewaysGetBgpPeerStatusFuture.azure.Future
1. VirtualNetworkGatewaysGetLearnedRoutesFuture.azure.Future
1. VirtualNetworkGatewaysGetVpnProfilePackageURLFuture.azure.Future
1. VirtualNetworkGatewaysGetVpnclientConnectionHealthFuture.azure.Future
1. VirtualNetworkGatewaysGetVpnclientIpsecParametersFuture.azure.Future
1. VirtualNetworkGatewaysResetFuture.azure.Future
1. VirtualNetworkGatewaysResetVpnClientSharedKeyFuture.azure.Future
1. VirtualNetworkGatewaysSetVpnclientIpsecParametersFuture.azure.Future
1. VirtualNetworkGatewaysStartPacketCaptureFuture.azure.Future
1. VirtualNetworkGatewaysStopPacketCaptureFuture.azure.Future
1. VirtualNetworkGatewaysUpdateTagsFuture.azure.Future
1. VirtualNetworkPeeringsCreateOrUpdateFuture.azure.Future
1. VirtualNetworkPeeringsDeleteFuture.azure.Future
1. VirtualNetworkTapsCreateOrUpdateFuture.azure.Future
1. VirtualNetworkTapsDeleteFuture.azure.Future
1. VirtualNetworksCreateOrUpdateFuture.azure.Future
1. VirtualNetworksDeleteFuture.azure.Future
1. VirtualRouterPeeringsCreateOrUpdateFuture.azure.Future
1. VirtualRouterPeeringsDeleteFuture.azure.Future
1. VirtualRoutersCreateOrUpdateFuture.azure.Future
1. VirtualRoutersDeleteFuture.azure.Future
1. VirtualWansCreateOrUpdateFuture.azure.Future
1. VirtualWansDeleteFuture.azure.Future
1. VpnConnectionsCreateOrUpdateFuture.azure.Future
1. VpnConnectionsDeleteFuture.azure.Future
1. VpnGatewaysCreateOrUpdateFuture.azure.Future
1. VpnGatewaysDeleteFuture.azure.Future
1. VpnGatewaysResetFuture.azure.Future
1. VpnServerConfigurationsAssociatedWithVirtualWanListFuture.azure.Future
1. VpnServerConfigurationsCreateOrUpdateFuture.azure.Future
1. VpnServerConfigurationsDeleteFuture.azure.Future
1. VpnSitesConfigurationDownloadFuture.azure.Future
1. VpnSitesCreateOrUpdateFuture.azure.Future
1. VpnSitesDeleteFuture.azure.Future
1. WatchersCheckConnectivityFuture.azure.Future
1. WatchersDeleteFuture.azure.Future
1. WatchersGetAzureReachabilityReportFuture.azure.Future
1. WatchersGetFlowLogStatusFuture.azure.Future
1. WatchersGetNetworkConfigurationDiagnosticFuture.azure.Future
1. WatchersGetNextHopFuture.azure.Future
1. WatchersGetTroubleshootingFuture.azure.Future
1. WatchersGetTroubleshootingResultFuture.azure.Future
1. WatchersGetVMSecurityRulesFuture.azure.Future
1. WatchersListAvailableProvidersFuture.azure.Future
1. WatchersSetFlowLogConfigurationFuture.azure.Future
1. WatchersVerifyIPFlowFuture.azure.Future
1. WebApplicationFirewallPoliciesDeleteFuture.azure.Future

## Struct Changes

### New Struct Fields

1. ApplicationGatewaysBackendHealthFuture.Result
1. ApplicationGatewaysBackendHealthFuture.azure.FutureAPI
1. ApplicationGatewaysBackendHealthOnDemandFuture.Result
1. ApplicationGatewaysBackendHealthOnDemandFuture.azure.FutureAPI
1. ApplicationGatewaysCreateOrUpdateFuture.Result
1. ApplicationGatewaysCreateOrUpdateFuture.azure.FutureAPI
1. ApplicationGatewaysDeleteFuture.Result
1. ApplicationGatewaysDeleteFuture.azure.FutureAPI
1. ApplicationGatewaysStartFuture.Result
1. ApplicationGatewaysStartFuture.azure.FutureAPI
1. ApplicationGatewaysStopFuture.Result
1. ApplicationGatewaysStopFuture.azure.FutureAPI
1. ApplicationSecurityGroupsCreateOrUpdateFuture.Result
1. ApplicationSecurityGroupsCreateOrUpdateFuture.azure.FutureAPI
1. ApplicationSecurityGroupsDeleteFuture.Result
1. ApplicationSecurityGroupsDeleteFuture.azure.FutureAPI
1. AzureFirewallsCreateOrUpdateFuture.Result
1. AzureFirewallsCreateOrUpdateFuture.azure.FutureAPI
1. AzureFirewallsDeleteFuture.Result
1. AzureFirewallsDeleteFuture.azure.FutureAPI
1. AzureFirewallsUpdateTagsFuture.Result
1. AzureFirewallsUpdateTagsFuture.azure.FutureAPI
1. BastionHostsCreateOrUpdateFuture.Result
1. BastionHostsCreateOrUpdateFuture.azure.FutureAPI
1. BastionHostsDeleteFuture.Result
1. BastionHostsDeleteFuture.azure.FutureAPI
1. ConnectionMonitorsCreateOrUpdateFuture.Result
1. ConnectionMonitorsCreateOrUpdateFuture.azure.FutureAPI
1. ConnectionMonitorsDeleteFuture.Result
1. ConnectionMonitorsDeleteFuture.azure.FutureAPI
1. ConnectionMonitorsQueryFuture.Result
1. ConnectionMonitorsQueryFuture.azure.FutureAPI
1. ConnectionMonitorsStartFuture.Result
1. ConnectionMonitorsStartFuture.azure.FutureAPI
1. ConnectionMonitorsStopFuture.Result
1. ConnectionMonitorsStopFuture.azure.FutureAPI
1. DdosCustomPoliciesCreateOrUpdateFuture.Result
1. DdosCustomPoliciesCreateOrUpdateFuture.azure.FutureAPI
1. DdosCustomPoliciesDeleteFuture.Result
1. DdosCustomPoliciesDeleteFuture.azure.FutureAPI
1. DdosProtectionPlansCreateOrUpdateFuture.Result
1. DdosProtectionPlansCreateOrUpdateFuture.azure.FutureAPI
1. DdosProtectionPlansDeleteFuture.Result
1. DdosProtectionPlansDeleteFuture.azure.FutureAPI
1. DeleteBastionShareableLinkFuture.Result
1. DeleteBastionShareableLinkFuture.azure.FutureAPI
1. ExpressRouteCircuitAuthorizationsCreateOrUpdateFuture.Result
1. ExpressRouteCircuitAuthorizationsCreateOrUpdateFuture.azure.FutureAPI
1. ExpressRouteCircuitAuthorizationsDeleteFuture.Result
1. ExpressRouteCircuitAuthorizationsDeleteFuture.azure.FutureAPI
1. ExpressRouteCircuitConnectionsCreateOrUpdateFuture.Result
1. ExpressRouteCircuitConnectionsCreateOrUpdateFuture.azure.FutureAPI
1. ExpressRouteCircuitConnectionsDeleteFuture.Result
1. ExpressRouteCircuitConnectionsDeleteFuture.azure.FutureAPI
1. ExpressRouteCircuitPeeringsCreateOrUpdateFuture.Result
1. ExpressRouteCircuitPeeringsCreateOrUpdateFuture.azure.FutureAPI
1. ExpressRouteCircuitPeeringsDeleteFuture.Result
1. ExpressRouteCircuitPeeringsDeleteFuture.azure.FutureAPI
1. ExpressRouteCircuitsCreateOrUpdateFuture.Result
1. ExpressRouteCircuitsCreateOrUpdateFuture.azure.FutureAPI
1. ExpressRouteCircuitsDeleteFuture.Result
1. ExpressRouteCircuitsDeleteFuture.azure.FutureAPI
1. ExpressRouteCircuitsListArpTableFuture.Result
1. ExpressRouteCircuitsListArpTableFuture.azure.FutureAPI
1. ExpressRouteCircuitsListRoutesTableFuture.Result
1. ExpressRouteCircuitsListRoutesTableFuture.azure.FutureAPI
1. ExpressRouteCircuitsListRoutesTableSummaryFuture.Result
1. ExpressRouteCircuitsListRoutesTableSummaryFuture.azure.FutureAPI
1. ExpressRouteConnectionsCreateOrUpdateFuture.Result
1. ExpressRouteConnectionsCreateOrUpdateFuture.azure.FutureAPI
1. ExpressRouteConnectionsDeleteFuture.Result
1. ExpressRouteConnectionsDeleteFuture.azure.FutureAPI
1. ExpressRouteCrossConnectionPeeringsCreateOrUpdateFuture.Result
1. ExpressRouteCrossConnectionPeeringsCreateOrUpdateFuture.azure.FutureAPI
1. ExpressRouteCrossConnectionPeeringsDeleteFuture.Result
1. ExpressRouteCrossConnectionPeeringsDeleteFuture.azure.FutureAPI
1. ExpressRouteCrossConnectionsCreateOrUpdateFuture.Result
1. ExpressRouteCrossConnectionsCreateOrUpdateFuture.azure.FutureAPI
1. ExpressRouteCrossConnectionsListArpTableFuture.Result
1. ExpressRouteCrossConnectionsListArpTableFuture.azure.FutureAPI
1. ExpressRouteCrossConnectionsListRoutesTableFuture.Result
1. ExpressRouteCrossConnectionsListRoutesTableFuture.azure.FutureAPI
1. ExpressRouteCrossConnectionsListRoutesTableSummaryFuture.Result
1. ExpressRouteCrossConnectionsListRoutesTableSummaryFuture.azure.FutureAPI
1. ExpressRouteGatewaysCreateOrUpdateFuture.Result
1. ExpressRouteGatewaysCreateOrUpdateFuture.azure.FutureAPI
1. ExpressRouteGatewaysDeleteFuture.Result
1. ExpressRouteGatewaysDeleteFuture.azure.FutureAPI
1. ExpressRoutePortsCreateOrUpdateFuture.Result
1. ExpressRoutePortsCreateOrUpdateFuture.azure.FutureAPI
1. ExpressRoutePortsDeleteFuture.Result
1. ExpressRoutePortsDeleteFuture.azure.FutureAPI
1. FirewallPoliciesCreateOrUpdateFuture.Result
1. FirewallPoliciesCreateOrUpdateFuture.azure.FutureAPI
1. FirewallPoliciesDeleteFuture.Result
1. FirewallPoliciesDeleteFuture.azure.FutureAPI
1. FirewallPolicyRuleGroupsCreateOrUpdateFuture.Result
1. FirewallPolicyRuleGroupsCreateOrUpdateFuture.azure.FutureAPI
1. FirewallPolicyRuleGroupsDeleteFuture.Result
1. FirewallPolicyRuleGroupsDeleteFuture.azure.FutureAPI
1. GeneratevirtualwanvpnserverconfigurationvpnprofileFuture.Result
1. GeneratevirtualwanvpnserverconfigurationvpnprofileFuture.azure.FutureAPI
1. GetActiveSessionsAllFuture.Result
1. GetActiveSessionsAllFuture.azure.FutureAPI
1. GetActiveSessionsFuture.Result
1. GetActiveSessionsFuture.azure.FutureAPI
1. IPGroupsCreateOrUpdateFuture.Result
1. IPGroupsCreateOrUpdateFuture.azure.FutureAPI
1. IPGroupsDeleteFuture.Result
1. IPGroupsDeleteFuture.azure.FutureAPI
1. InboundNatRulesCreateOrUpdateFuture.Result
1. InboundNatRulesCreateOrUpdateFuture.azure.FutureAPI
1. InboundNatRulesDeleteFuture.Result
1. InboundNatRulesDeleteFuture.azure.FutureAPI
1. InterfaceTapConfigurationsCreateOrUpdateFuture.Result
1. InterfaceTapConfigurationsCreateOrUpdateFuture.azure.FutureAPI
1. InterfaceTapConfigurationsDeleteFuture.Result
1. InterfaceTapConfigurationsDeleteFuture.azure.FutureAPI
1. InterfacesCreateOrUpdateFuture.Result
1. InterfacesCreateOrUpdateFuture.azure.FutureAPI
1. InterfacesDeleteFuture.Result
1. InterfacesDeleteFuture.azure.FutureAPI
1. InterfacesGetEffectiveRouteTableFuture.Result
1. InterfacesGetEffectiveRouteTableFuture.azure.FutureAPI
1. InterfacesListEffectiveNetworkSecurityGroupsFuture.Result
1. InterfacesListEffectiveNetworkSecurityGroupsFuture.azure.FutureAPI
1. LoadBalancersCreateOrUpdateFuture.Result
1. LoadBalancersCreateOrUpdateFuture.azure.FutureAPI
1. LoadBalancersDeleteFuture.Result
1. LoadBalancersDeleteFuture.azure.FutureAPI
1. LocalNetworkGatewaysCreateOrUpdateFuture.Result
1. LocalNetworkGatewaysCreateOrUpdateFuture.azure.FutureAPI
1. LocalNetworkGatewaysDeleteFuture.Result
1. LocalNetworkGatewaysDeleteFuture.azure.FutureAPI
1. NatGatewaysCreateOrUpdateFuture.Result
1. NatGatewaysCreateOrUpdateFuture.azure.FutureAPI
1. NatGatewaysDeleteFuture.Result
1. NatGatewaysDeleteFuture.azure.FutureAPI
1. P2sVpnGatewaysCreateOrUpdateFuture.Result
1. P2sVpnGatewaysCreateOrUpdateFuture.azure.FutureAPI
1. P2sVpnGatewaysDeleteFuture.Result
1. P2sVpnGatewaysDeleteFuture.azure.FutureAPI
1. P2sVpnGatewaysGenerateVpnProfileFuture.Result
1. P2sVpnGatewaysGenerateVpnProfileFuture.azure.FutureAPI
1. P2sVpnGatewaysGetP2sVpnConnectionHealthDetailedFuture.Result
1. P2sVpnGatewaysGetP2sVpnConnectionHealthDetailedFuture.azure.FutureAPI
1. P2sVpnGatewaysGetP2sVpnConnectionHealthFuture.Result
1. P2sVpnGatewaysGetP2sVpnConnectionHealthFuture.azure.FutureAPI
1. PacketCapturesCreateFuture.Result
1. PacketCapturesCreateFuture.azure.FutureAPI
1. PacketCapturesDeleteFuture.Result
1. PacketCapturesDeleteFuture.azure.FutureAPI
1. PacketCapturesGetStatusFuture.Result
1. PacketCapturesGetStatusFuture.azure.FutureAPI
1. PacketCapturesStopFuture.Result
1. PacketCapturesStopFuture.azure.FutureAPI
1. PrivateEndpointsCreateOrUpdateFuture.Result
1. PrivateEndpointsCreateOrUpdateFuture.azure.FutureAPI
1. PrivateEndpointsDeleteFuture.Result
1. PrivateEndpointsDeleteFuture.azure.FutureAPI
1. PrivateLinkServicesCheckPrivateLinkServiceVisibilityByResourceGroupFuture.Result
1. PrivateLinkServicesCheckPrivateLinkServiceVisibilityByResourceGroupFuture.azure.FutureAPI
1. PrivateLinkServicesCheckPrivateLinkServiceVisibilityFuture.Result
1. PrivateLinkServicesCheckPrivateLinkServiceVisibilityFuture.azure.FutureAPI
1. PrivateLinkServicesCreateOrUpdateFuture.Result
1. PrivateLinkServicesCreateOrUpdateFuture.azure.FutureAPI
1. PrivateLinkServicesDeleteFuture.Result
1. PrivateLinkServicesDeleteFuture.azure.FutureAPI
1. PrivateLinkServicesDeletePrivateEndpointConnectionFuture.Result
1. PrivateLinkServicesDeletePrivateEndpointConnectionFuture.azure.FutureAPI
1. ProfilesDeleteFuture.Result
1. ProfilesDeleteFuture.azure.FutureAPI
1. PublicIPAddressesCreateOrUpdateFuture.Result
1. PublicIPAddressesCreateOrUpdateFuture.azure.FutureAPI
1. PublicIPAddressesDeleteFuture.Result
1. PublicIPAddressesDeleteFuture.azure.FutureAPI
1. PublicIPPrefixesCreateOrUpdateFuture.Result
1. PublicIPPrefixesCreateOrUpdateFuture.azure.FutureAPI
1. PublicIPPrefixesDeleteFuture.Result
1. PublicIPPrefixesDeleteFuture.azure.FutureAPI
1. PutBastionShareableLinkAllFuture.Result
1. PutBastionShareableLinkAllFuture.azure.FutureAPI
1. PutBastionShareableLinkFuture.Result
1. PutBastionShareableLinkFuture.azure.FutureAPI
1. RouteFilterRulesCreateOrUpdateFuture.Result
1. RouteFilterRulesCreateOrUpdateFuture.azure.FutureAPI
1. RouteFilterRulesDeleteFuture.Result
1. RouteFilterRulesDeleteFuture.azure.FutureAPI
1. RouteFiltersCreateOrUpdateFuture.Result
1. RouteFiltersCreateOrUpdateFuture.azure.FutureAPI
1. RouteFiltersDeleteFuture.Result
1. RouteFiltersDeleteFuture.azure.FutureAPI
1. RouteTablesCreateOrUpdateFuture.Result
1. RouteTablesCreateOrUpdateFuture.azure.FutureAPI
1. RouteTablesDeleteFuture.Result
1. RouteTablesDeleteFuture.azure.FutureAPI
1. RoutesCreateOrUpdateFuture.Result
1. RoutesCreateOrUpdateFuture.azure.FutureAPI
1. RoutesDeleteFuture.Result
1. RoutesDeleteFuture.azure.FutureAPI
1. SecurityGroupsCreateOrUpdateFuture.Result
1. SecurityGroupsCreateOrUpdateFuture.azure.FutureAPI
1. SecurityGroupsDeleteFuture.Result
1. SecurityGroupsDeleteFuture.azure.FutureAPI
1. SecurityRulesCreateOrUpdateFuture.Result
1. SecurityRulesCreateOrUpdateFuture.azure.FutureAPI
1. SecurityRulesDeleteFuture.Result
1. SecurityRulesDeleteFuture.azure.FutureAPI
1. ServiceEndpointPoliciesCreateOrUpdateFuture.Result
1. ServiceEndpointPoliciesCreateOrUpdateFuture.azure.FutureAPI
1. ServiceEndpointPoliciesDeleteFuture.Result
1. ServiceEndpointPoliciesDeleteFuture.azure.FutureAPI
1. ServiceEndpointPolicyDefinitionsCreateOrUpdateFuture.Result
1. ServiceEndpointPolicyDefinitionsCreateOrUpdateFuture.azure.FutureAPI
1. ServiceEndpointPolicyDefinitionsDeleteFuture.Result
1. ServiceEndpointPolicyDefinitionsDeleteFuture.azure.FutureAPI
1. SubnetsCreateOrUpdateFuture.Result
1. SubnetsCreateOrUpdateFuture.azure.FutureAPI
1. SubnetsDeleteFuture.Result
1. SubnetsDeleteFuture.azure.FutureAPI
1. SubnetsPrepareNetworkPoliciesFuture.Result
1. SubnetsPrepareNetworkPoliciesFuture.azure.FutureAPI
1. SubnetsUnprepareNetworkPoliciesFuture.Result
1. SubnetsUnprepareNetworkPoliciesFuture.azure.FutureAPI
1. VirtualHubRouteTableV2sCreateOrUpdateFuture.Result
1. VirtualHubRouteTableV2sCreateOrUpdateFuture.azure.FutureAPI
1. VirtualHubRouteTableV2sDeleteFuture.Result
1. VirtualHubRouteTableV2sDeleteFuture.azure.FutureAPI
1. VirtualHubsCreateOrUpdateFuture.Result
1. VirtualHubsCreateOrUpdateFuture.azure.FutureAPI
1. VirtualHubsDeleteFuture.Result
1. VirtualHubsDeleteFuture.azure.FutureAPI
1. VirtualNetworkGatewayConnectionsCreateOrUpdateFuture.Result
1. VirtualNetworkGatewayConnectionsCreateOrUpdateFuture.azure.FutureAPI
1. VirtualNetworkGatewayConnectionsDeleteFuture.Result
1. VirtualNetworkGatewayConnectionsDeleteFuture.azure.FutureAPI
1. VirtualNetworkGatewayConnectionsResetSharedKeyFuture.Result
1. VirtualNetworkGatewayConnectionsResetSharedKeyFuture.azure.FutureAPI
1. VirtualNetworkGatewayConnectionsSetSharedKeyFuture.Result
1. VirtualNetworkGatewayConnectionsSetSharedKeyFuture.azure.FutureAPI
1. VirtualNetworkGatewayConnectionsStartPacketCaptureFuture.Result
1. VirtualNetworkGatewayConnectionsStartPacketCaptureFuture.azure.FutureAPI
1. VirtualNetworkGatewayConnectionsStopPacketCaptureFuture.Result
1. VirtualNetworkGatewayConnectionsStopPacketCaptureFuture.azure.FutureAPI
1. VirtualNetworkGatewayConnectionsUpdateTagsFuture.Result
1. VirtualNetworkGatewayConnectionsUpdateTagsFuture.azure.FutureAPI
1. VirtualNetworkGatewaysCreateOrUpdateFuture.Result
1. VirtualNetworkGatewaysCreateOrUpdateFuture.azure.FutureAPI
1. VirtualNetworkGatewaysDeleteFuture.Result
1. VirtualNetworkGatewaysDeleteFuture.azure.FutureAPI
1. VirtualNetworkGatewaysGenerateVpnProfileFuture.Result
1. VirtualNetworkGatewaysGenerateVpnProfileFuture.azure.FutureAPI
1. VirtualNetworkGatewaysGeneratevpnclientpackageFuture.Result
1. VirtualNetworkGatewaysGeneratevpnclientpackageFuture.azure.FutureAPI
1. VirtualNetworkGatewaysGetAdvertisedRoutesFuture.Result
1. VirtualNetworkGatewaysGetAdvertisedRoutesFuture.azure.FutureAPI
1. VirtualNetworkGatewaysGetBgpPeerStatusFuture.Result
1. VirtualNetworkGatewaysGetBgpPeerStatusFuture.azure.FutureAPI
1. VirtualNetworkGatewaysGetLearnedRoutesFuture.Result
1. VirtualNetworkGatewaysGetLearnedRoutesFuture.azure.FutureAPI
1. VirtualNetworkGatewaysGetVpnProfilePackageURLFuture.Result
1. VirtualNetworkGatewaysGetVpnProfilePackageURLFuture.azure.FutureAPI
1. VirtualNetworkGatewaysGetVpnclientConnectionHealthFuture.Result
1. VirtualNetworkGatewaysGetVpnclientConnectionHealthFuture.azure.FutureAPI
1. VirtualNetworkGatewaysGetVpnclientIpsecParametersFuture.Result
1. VirtualNetworkGatewaysGetVpnclientIpsecParametersFuture.azure.FutureAPI
1. VirtualNetworkGatewaysResetFuture.Result
1. VirtualNetworkGatewaysResetFuture.azure.FutureAPI
1. VirtualNetworkGatewaysResetVpnClientSharedKeyFuture.Result
1. VirtualNetworkGatewaysResetVpnClientSharedKeyFuture.azure.FutureAPI
1. VirtualNetworkGatewaysSetVpnclientIpsecParametersFuture.Result
1. VirtualNetworkGatewaysSetVpnclientIpsecParametersFuture.azure.FutureAPI
1. VirtualNetworkGatewaysStartPacketCaptureFuture.Result
1. VirtualNetworkGatewaysStartPacketCaptureFuture.azure.FutureAPI
1. VirtualNetworkGatewaysStopPacketCaptureFuture.Result
1. VirtualNetworkGatewaysStopPacketCaptureFuture.azure.FutureAPI
1. VirtualNetworkGatewaysUpdateTagsFuture.Result
1. VirtualNetworkGatewaysUpdateTagsFuture.azure.FutureAPI
1. VirtualNetworkPeeringsCreateOrUpdateFuture.Result
1. VirtualNetworkPeeringsCreateOrUpdateFuture.azure.FutureAPI
1. VirtualNetworkPeeringsDeleteFuture.Result
1. VirtualNetworkPeeringsDeleteFuture.azure.FutureAPI
1. VirtualNetworkTapsCreateOrUpdateFuture.Result
1. VirtualNetworkTapsCreateOrUpdateFuture.azure.FutureAPI
1. VirtualNetworkTapsDeleteFuture.Result
1. VirtualNetworkTapsDeleteFuture.azure.FutureAPI
1. VirtualNetworksCreateOrUpdateFuture.Result
1. VirtualNetworksCreateOrUpdateFuture.azure.FutureAPI
1. VirtualNetworksDeleteFuture.Result
1. VirtualNetworksDeleteFuture.azure.FutureAPI
1. VirtualRouterPeeringsCreateOrUpdateFuture.Result
1. VirtualRouterPeeringsCreateOrUpdateFuture.azure.FutureAPI
1. VirtualRouterPeeringsDeleteFuture.Result
1. VirtualRouterPeeringsDeleteFuture.azure.FutureAPI
1. VirtualRoutersCreateOrUpdateFuture.Result
1. VirtualRoutersCreateOrUpdateFuture.azure.FutureAPI
1. VirtualRoutersDeleteFuture.Result
1. VirtualRoutersDeleteFuture.azure.FutureAPI
1. VirtualWansCreateOrUpdateFuture.Result
1. VirtualWansCreateOrUpdateFuture.azure.FutureAPI
1. VirtualWansDeleteFuture.Result
1. VirtualWansDeleteFuture.azure.FutureAPI
1. VpnConnectionsCreateOrUpdateFuture.Result
1. VpnConnectionsCreateOrUpdateFuture.azure.FutureAPI
1. VpnConnectionsDeleteFuture.Result
1. VpnConnectionsDeleteFuture.azure.FutureAPI
1. VpnGatewaysCreateOrUpdateFuture.Result
1. VpnGatewaysCreateOrUpdateFuture.azure.FutureAPI
1. VpnGatewaysDeleteFuture.Result
1. VpnGatewaysDeleteFuture.azure.FutureAPI
1. VpnGatewaysResetFuture.Result
1. VpnGatewaysResetFuture.azure.FutureAPI
1. VpnServerConfigurationsAssociatedWithVirtualWanListFuture.Result
1. VpnServerConfigurationsAssociatedWithVirtualWanListFuture.azure.FutureAPI
1. VpnServerConfigurationsCreateOrUpdateFuture.Result
1. VpnServerConfigurationsCreateOrUpdateFuture.azure.FutureAPI
1. VpnServerConfigurationsDeleteFuture.Result
1. VpnServerConfigurationsDeleteFuture.azure.FutureAPI
1. VpnSitesConfigurationDownloadFuture.Result
1. VpnSitesConfigurationDownloadFuture.azure.FutureAPI
1. VpnSitesCreateOrUpdateFuture.Result
1. VpnSitesCreateOrUpdateFuture.azure.FutureAPI
1. VpnSitesDeleteFuture.Result
1. VpnSitesDeleteFuture.azure.FutureAPI
1. WatchersCheckConnectivityFuture.Result
1. WatchersCheckConnectivityFuture.azure.FutureAPI
1. WatchersDeleteFuture.Result
1. WatchersDeleteFuture.azure.FutureAPI
1. WatchersGetAzureReachabilityReportFuture.Result
1. WatchersGetAzureReachabilityReportFuture.azure.FutureAPI
1. WatchersGetFlowLogStatusFuture.Result
1. WatchersGetFlowLogStatusFuture.azure.FutureAPI
1. WatchersGetNetworkConfigurationDiagnosticFuture.Result
1. WatchersGetNetworkConfigurationDiagnosticFuture.azure.FutureAPI
1. WatchersGetNextHopFuture.Result
1. WatchersGetNextHopFuture.azure.FutureAPI
1. WatchersGetTroubleshootingFuture.Result
1. WatchersGetTroubleshootingFuture.azure.FutureAPI
1. WatchersGetTroubleshootingResultFuture.Result
1. WatchersGetTroubleshootingResultFuture.azure.FutureAPI
1. WatchersGetVMSecurityRulesFuture.Result
1. WatchersGetVMSecurityRulesFuture.azure.FutureAPI
1. WatchersListAvailableProvidersFuture.Result
1. WatchersListAvailableProvidersFuture.azure.FutureAPI
1. WatchersSetFlowLogConfigurationFuture.Result
1. WatchersSetFlowLogConfigurationFuture.azure.FutureAPI
1. WatchersVerifyIPFlowFuture.Result
1. WatchersVerifyIPFlowFuture.azure.FutureAPI
1. WebApplicationFirewallPoliciesDeleteFuture.Result
1. WebApplicationFirewallPoliciesDeleteFuture.azure.FutureAPI
