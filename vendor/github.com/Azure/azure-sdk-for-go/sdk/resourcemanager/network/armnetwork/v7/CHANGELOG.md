# Release History

## 7.2.0 (2025-11-20)
### Features Added

- New enum type `AccessMode` with values `AccessModeDefault`, `AccessModeRestricted`
- New enum type `ConnectionAuthenticationType` with values `ConnectionAuthenticationTypeCertificate`, `ConnectionAuthenticationTypePSK`
- New enum type `LoadBalancerScope` with values `LoadBalancerScopePrivate`, `LoadBalancerScopePublic`
- New enum type `RouteTableUsageMode` with values `RouteTableUsageModeManagedOnly`, `RouteTableUsageModeUseExisting`
- New struct `CertificateAuthentication`
- New field `EnableL4ClientIPPreservation` in struct `ApplicationGatewayBackendSettingsPropertiesFormat`
- New field `EnableProbeProxyProtocolHeader` in struct `ApplicationGatewayOnDemandProbe`
- New field `EnableProbeProxyProtocolHeader` in struct `ApplicationGatewayProbePropertiesFormat`
- New field `Scope` in struct `LoadBalancerPropertiesFormat`
- New field `RouteTableUsageMode` in struct `ManagerRoutingConfigurationPropertiesFormat`
- New field `AccessMode` in struct `PrivateLinkServiceProperties`
- New field `AuthenticationType`, `CertificateAuthentication` in struct `VirtualNetworkGatewayConnectionPropertiesFormat`


## 7.1.0 (2025-10-23)
### Features Added

- New value `TransportProtocolQuic` added to enum type `TransportProtocol`
- New enum type `AzureFirewallPacketCaptureOperationType` with values `AzureFirewallPacketCaptureOperationTypeStart`, `AzureFirewallPacketCaptureOperationTypeStatus`, `AzureFirewallPacketCaptureOperationTypeStop`
- New enum type `AzureFirewallPacketCaptureResponseCode` with values `AzureFirewallPacketCaptureResponseCodeAzureFirewallPacketCaptureCompleted`, `AzureFirewallPacketCaptureResponseCodeAzureFirewallPacketCaptureFailed`, `AzureFirewallPacketCaptureResponseCodeAzureFirewallPacketCaptureInProgress`, `AzureFirewallPacketCaptureResponseCodeAzureFirewallPacketCaptureNotInProgress`, `AzureFirewallPacketCaptureResponseCodeAzureFirewallPacketCaptureStartFailed`, `AzureFirewallPacketCaptureResponseCodeAzureFirewallPacketCaptureStartFailedToUpload`, `AzureFirewallPacketCaptureResponseCodeAzureFirewallPacketCaptureStartFailure`, `AzureFirewallPacketCaptureResponseCodeAzureFirewallPacketCaptureStartSucceeded`, `AzureFirewallPacketCaptureResponseCodeAzureFirewallPacketCaptureStopSucceeded`, `AzureFirewallPacketCaptureResponseCodeNotImplemented`
- New enum type `NvaNicType` with values `NvaNicTypeAdditionalPrivateNic`, `NvaNicTypeAdditionalPublicNic`, `NvaNicTypePrivateNic`, `NvaNicTypePublicNic`
- New function `*AzureFirewallsClient.BeginPacketCaptureOperation(context.Context, string, string, FirewallPacketCaptureParameters, *AzureFirewallsClientBeginPacketCaptureOperationOptions) (*runtime.Poller[AzureFirewallsClientPacketCaptureOperationResponse], error)`
- New function `*ClientFactory.NewSecurityPerimeterServiceTagsClient() *SecurityPerimeterServiceTagsClient`
- New function `NewSecurityPerimeterServiceTagsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*SecurityPerimeterServiceTagsClient, error)`
- New function `*SecurityPerimeterServiceTagsClient.NewListPager(string, *SecurityPerimeterServiceTagsClientListOptions) *runtime.Pager[SecurityPerimeterServiceTagsClientListResponse]`
- New function `*VPNServerConfigurationsClient.ListRadiusSecrets(context.Context, string, string, *VPNServerConfigurationsClientListRadiusSecretsOptions) (VPNServerConfigurationsClientListRadiusSecretsResponse, error)`
- New function `*VirtualNetworkGatewaysClient.ListRadiusSecrets(context.Context, string, string, *VirtualNetworkGatewaysClientListRadiusSecretsOptions) (VirtualNetworkGatewaysClientListRadiusSecretsResponse, error)`
- New struct `AzureFirewallPacketCaptureResponse`
- New struct `NspServiceTagsListResult`
- New struct `NspServiceTagsResource`
- New struct `NvaInVnetSubnetReferenceProperties`
- New struct `NvaInterfaceConfigurationsProperties`
- New struct `RadiusAuthServer`
- New struct `RadiusAuthServerListResult`
- New field `DedicatedBackendConnection`, `SniName`, `ValidateCertChainAndExpiry`, `ValidateSNI` in struct `ApplicationGatewayBackendHTTPSettingsPropertiesFormat`
- New field `ExtendedLocation` in struct `AzureFirewall`
- New field `Operation` in struct `FirewallPacketCaptureParameters`
- New field `NvaInterfaceConfigurations`, `PrivateIPAddress` in struct `VirtualAppliancePropertiesFormat`


## 7.0.0 (2025-05-22)
### Breaking Changes

- Type of `LoadBalancerHealthPerRulePerBackendAddress.NetworkInterfaceIPConfigurationID` has been changed from `*InterfaceIPConfiguration` to `*string`
- Function `*ConnectionMonitorsClient.BeginQuery` has been removed
- Function `*ConnectionMonitorsClient.BeginStart` has been removed

### Features Added

- New value `ApplicationGatewayFirewallUserSessionVariableClientAddrXFFHeader`, `ApplicationGatewayFirewallUserSessionVariableGeoLocationXFFHeader` added to enum type `ApplicationGatewayFirewallUserSessionVariable`
- New value `NatGatewaySKUNameStandardV2` added to enum type `NatGatewaySKUName`
- New value `PublicIPAddressSKUNameStandardV2` added to enum type `PublicIPAddressSKUName`
- New value `PublicIPPrefixSKUNameStandardV2` added to enum type `PublicIPPrefixSKUName`
- New enum type `AccessRuleDirection` with values `AccessRuleDirectionInbound`, `AccessRuleDirectionOutbound`
- New enum type `AdvertisedPublicPrefixPropertiesValidationState` with values `AdvertisedPublicPrefixPropertiesValidationStateAsnValidationFailed`, `AdvertisedPublicPrefixPropertiesValidationStateCertificateMissingInRoutingRegistry`, `AdvertisedPublicPrefixPropertiesValidationStateConfigured`, `AdvertisedPublicPrefixPropertiesValidationStateConfiguring`, `AdvertisedPublicPrefixPropertiesValidationStateInvalidSignatureEncoding`, `AdvertisedPublicPrefixPropertiesValidationStateManualValidationNeeded`, `AdvertisedPublicPrefixPropertiesValidationStateNotConfigured`, `AdvertisedPublicPrefixPropertiesValidationStateSignatureVerificationFailed`, `AdvertisedPublicPrefixPropertiesValidationStateValidationFailed`, `AdvertisedPublicPrefixPropertiesValidationStateValidationNeeded`
- New enum type `AssociationAccessMode` with values `AssociationAccessModeAudit`, `AssociationAccessModeEnforced`, `AssociationAccessModeLearning`
- New enum type `ConnectedGroupAddressOverlap` with values `ConnectedGroupAddressOverlapAllowed`, `ConnectedGroupAddressOverlapDisallowed`
- New enum type `ConnectedGroupPrivateEndpointsScale` with values `ConnectedGroupPrivateEndpointsScaleHighScale`, `ConnectedGroupPrivateEndpointsScaleStandard`
- New enum type `NspLinkProvisioningState` with values `NspLinkProvisioningStateAccepted`, `NspLinkProvisioningStateCreating`, `NspLinkProvisioningStateDeleting`, `NspLinkProvisioningStateFailed`, `NspLinkProvisioningStateSucceeded`, `NspLinkProvisioningStateUpdating`, `NspLinkProvisioningStateWaitForRemoteCompletion`
- New enum type `NspLinkStatus` with values `NspLinkStatusApproved`, `NspLinkStatusDisconnected`, `NspLinkStatusPending`, `NspLinkStatusRejected`
- New enum type `NspProvisioningState` with values `NspProvisioningStateAccepted`, `NspProvisioningStateCreating`, `NspProvisioningStateDeleting`, `NspProvisioningStateFailed`, `NspProvisioningStateSucceeded`, `NspProvisioningStateUpdating`
- New enum type `PeeringEnforcement` with values `PeeringEnforcementEnforced`, `PeeringEnforcementUnenforced`
- New enum type `VirtualNetworkGatewayMigrationPhase` with values `VirtualNetworkGatewayMigrationPhaseAbort`, `VirtualNetworkGatewayMigrationPhaseAbortSucceeded`, `VirtualNetworkGatewayMigrationPhaseCommit`, `VirtualNetworkGatewayMigrationPhaseCommitSucceeded`, `VirtualNetworkGatewayMigrationPhaseExecute`, `VirtualNetworkGatewayMigrationPhaseExecuteSucceeded`, `VirtualNetworkGatewayMigrationPhaseNone`, `VirtualNetworkGatewayMigrationPhasePrepare`, `VirtualNetworkGatewayMigrationPhasePrepareSucceeded`
- New enum type `VirtualNetworkGatewayMigrationState` with values `VirtualNetworkGatewayMigrationStateFailed`, `VirtualNetworkGatewayMigrationStateInProgress`, `VirtualNetworkGatewayMigrationStateNone`, `VirtualNetworkGatewayMigrationStateSucceeded`
- New enum type `VirtualNetworkGatewayMigrationType` with values `VirtualNetworkGatewayMigrationTypeUpgradeDeploymentToStandardIP`
- New function `*ClientFactory.NewSecurityPerimeterAccessRulesClient() *SecurityPerimeterAccessRulesClient`
- New function `*ClientFactory.NewSecurityPerimeterAssociableResourceTypesClient() *SecurityPerimeterAssociableResourceTypesClient`
- New function `*ClientFactory.NewSecurityPerimeterAssociationsClient() *SecurityPerimeterAssociationsClient`
- New function `*ClientFactory.NewSecurityPerimeterLinkReferencesClient() *SecurityPerimeterLinkReferencesClient`
- New function `*ClientFactory.NewSecurityPerimeterLinksClient() *SecurityPerimeterLinksClient`
- New function `*ClientFactory.NewSecurityPerimeterLoggingConfigurationsClient() *SecurityPerimeterLoggingConfigurationsClient`
- New function `*ClientFactory.NewSecurityPerimeterOperationStatusesClient() *SecurityPerimeterOperationStatusesClient`
- New function `*ClientFactory.NewSecurityPerimeterProfilesClient() *SecurityPerimeterProfilesClient`
- New function `*ClientFactory.NewSecurityPerimetersClient() *SecurityPerimetersClient`
- New function `NewSecurityPerimeterAccessRulesClient(string, azcore.TokenCredential, *arm.ClientOptions) (*SecurityPerimeterAccessRulesClient, error)`
- New function `*SecurityPerimeterAccessRulesClient.CreateOrUpdate(context.Context, string, string, string, string, NspAccessRule, *SecurityPerimeterAccessRulesClientCreateOrUpdateOptions) (SecurityPerimeterAccessRulesClientCreateOrUpdateResponse, error)`
- New function `*SecurityPerimeterAccessRulesClient.Delete(context.Context, string, string, string, string, *SecurityPerimeterAccessRulesClientDeleteOptions) (SecurityPerimeterAccessRulesClientDeleteResponse, error)`
- New function `*SecurityPerimeterAccessRulesClient.Get(context.Context, string, string, string, string, *SecurityPerimeterAccessRulesClientGetOptions) (SecurityPerimeterAccessRulesClientGetResponse, error)`
- New function `*SecurityPerimeterAccessRulesClient.NewListPager(string, string, string, *SecurityPerimeterAccessRulesClientListOptions) *runtime.Pager[SecurityPerimeterAccessRulesClientListResponse]`
- New function `*SecurityPerimeterAccessRulesClient.Reconcile(context.Context, string, string, string, string, any, *SecurityPerimeterAccessRulesClientReconcileOptions) (SecurityPerimeterAccessRulesClientReconcileResponse, error)`
- New function `NewSecurityPerimeterAssociableResourceTypesClient(string, azcore.TokenCredential, *arm.ClientOptions) (*SecurityPerimeterAssociableResourceTypesClient, error)`
- New function `*SecurityPerimeterAssociableResourceTypesClient.NewListPager(string, *SecurityPerimeterAssociableResourceTypesClientListOptions) *runtime.Pager[SecurityPerimeterAssociableResourceTypesClientListResponse]`
- New function `NewSecurityPerimeterAssociationsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*SecurityPerimeterAssociationsClient, error)`
- New function `*SecurityPerimeterAssociationsClient.BeginCreateOrUpdate(context.Context, string, string, string, NspAssociation, *SecurityPerimeterAssociationsClientBeginCreateOrUpdateOptions) (*runtime.Poller[SecurityPerimeterAssociationsClientCreateOrUpdateResponse], error)`
- New function `*SecurityPerimeterAssociationsClient.BeginDelete(context.Context, string, string, string, *SecurityPerimeterAssociationsClientBeginDeleteOptions) (*runtime.Poller[SecurityPerimeterAssociationsClientDeleteResponse], error)`
- New function `*SecurityPerimeterAssociationsClient.Get(context.Context, string, string, string, *SecurityPerimeterAssociationsClientGetOptions) (SecurityPerimeterAssociationsClientGetResponse, error)`
- New function `*SecurityPerimeterAssociationsClient.NewListPager(string, string, *SecurityPerimeterAssociationsClientListOptions) *runtime.Pager[SecurityPerimeterAssociationsClientListResponse]`
- New function `*SecurityPerimeterAssociationsClient.Reconcile(context.Context, string, string, string, any, *SecurityPerimeterAssociationsClientReconcileOptions) (SecurityPerimeterAssociationsClientReconcileResponse, error)`
- New function `NewSecurityPerimeterLinkReferencesClient(string, azcore.TokenCredential, *arm.ClientOptions) (*SecurityPerimeterLinkReferencesClient, error)`
- New function `*SecurityPerimeterLinkReferencesClient.BeginDelete(context.Context, string, string, string, *SecurityPerimeterLinkReferencesClientBeginDeleteOptions) (*runtime.Poller[SecurityPerimeterLinkReferencesClientDeleteResponse], error)`
- New function `*SecurityPerimeterLinkReferencesClient.Get(context.Context, string, string, string, *SecurityPerimeterLinkReferencesClientGetOptions) (SecurityPerimeterLinkReferencesClientGetResponse, error)`
- New function `*SecurityPerimeterLinkReferencesClient.NewListPager(string, string, *SecurityPerimeterLinkReferencesClientListOptions) *runtime.Pager[SecurityPerimeterLinkReferencesClientListResponse]`
- New function `NewSecurityPerimeterLinksClient(string, azcore.TokenCredential, *arm.ClientOptions) (*SecurityPerimeterLinksClient, error)`
- New function `*SecurityPerimeterLinksClient.CreateOrUpdate(context.Context, string, string, string, NspLink, *SecurityPerimeterLinksClientCreateOrUpdateOptions) (SecurityPerimeterLinksClientCreateOrUpdateResponse, error)`
- New function `*SecurityPerimeterLinksClient.BeginDelete(context.Context, string, string, string, *SecurityPerimeterLinksClientBeginDeleteOptions) (*runtime.Poller[SecurityPerimeterLinksClientDeleteResponse], error)`
- New function `*SecurityPerimeterLinksClient.Get(context.Context, string, string, string, *SecurityPerimeterLinksClientGetOptions) (SecurityPerimeterLinksClientGetResponse, error)`
- New function `*SecurityPerimeterLinksClient.NewListPager(string, string, *SecurityPerimeterLinksClientListOptions) *runtime.Pager[SecurityPerimeterLinksClientListResponse]`
- New function `NewSecurityPerimeterLoggingConfigurationsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*SecurityPerimeterLoggingConfigurationsClient, error)`
- New function `*SecurityPerimeterLoggingConfigurationsClient.CreateOrUpdate(context.Context, string, string, string, NspLoggingConfiguration, *SecurityPerimeterLoggingConfigurationsClientCreateOrUpdateOptions) (SecurityPerimeterLoggingConfigurationsClientCreateOrUpdateResponse, error)`
- New function `*SecurityPerimeterLoggingConfigurationsClient.Delete(context.Context, string, string, string, *SecurityPerimeterLoggingConfigurationsClientDeleteOptions) (SecurityPerimeterLoggingConfigurationsClientDeleteResponse, error)`
- New function `*SecurityPerimeterLoggingConfigurationsClient.Get(context.Context, string, string, string, *SecurityPerimeterLoggingConfigurationsClientGetOptions) (SecurityPerimeterLoggingConfigurationsClientGetResponse, error)`
- New function `*SecurityPerimeterLoggingConfigurationsClient.NewListPager(string, string, *SecurityPerimeterLoggingConfigurationsClientListOptions) *runtime.Pager[SecurityPerimeterLoggingConfigurationsClientListResponse]`
- New function `NewSecurityPerimeterOperationStatusesClient(string, azcore.TokenCredential, *arm.ClientOptions) (*SecurityPerimeterOperationStatusesClient, error)`
- New function `*SecurityPerimeterOperationStatusesClient.Get(context.Context, string, string, *SecurityPerimeterOperationStatusesClientGetOptions) (SecurityPerimeterOperationStatusesClientGetResponse, error)`
- New function `NewSecurityPerimeterProfilesClient(string, azcore.TokenCredential, *arm.ClientOptions) (*SecurityPerimeterProfilesClient, error)`
- New function `*SecurityPerimeterProfilesClient.CreateOrUpdate(context.Context, string, string, string, NspProfile, *SecurityPerimeterProfilesClientCreateOrUpdateOptions) (SecurityPerimeterProfilesClientCreateOrUpdateResponse, error)`
- New function `*SecurityPerimeterProfilesClient.Delete(context.Context, string, string, string, *SecurityPerimeterProfilesClientDeleteOptions) (SecurityPerimeterProfilesClientDeleteResponse, error)`
- New function `*SecurityPerimeterProfilesClient.Get(context.Context, string, string, string, *SecurityPerimeterProfilesClientGetOptions) (SecurityPerimeterProfilesClientGetResponse, error)`
- New function `*SecurityPerimeterProfilesClient.NewListPager(string, string, *SecurityPerimeterProfilesClientListOptions) *runtime.Pager[SecurityPerimeterProfilesClientListResponse]`
- New function `NewSecurityPerimetersClient(string, azcore.TokenCredential, *arm.ClientOptions) (*SecurityPerimetersClient, error)`
- New function `*SecurityPerimetersClient.CreateOrUpdate(context.Context, string, string, SecurityPerimeter, *SecurityPerimetersClientCreateOrUpdateOptions) (SecurityPerimetersClientCreateOrUpdateResponse, error)`
- New function `*SecurityPerimetersClient.BeginDelete(context.Context, string, string, *SecurityPerimetersClientBeginDeleteOptions) (*runtime.Poller[SecurityPerimetersClientDeleteResponse], error)`
- New function `*SecurityPerimetersClient.Get(context.Context, string, string, *SecurityPerimetersClientGetOptions) (SecurityPerimetersClientGetResponse, error)`
- New function `*SecurityPerimetersClient.NewListBySubscriptionPager(*SecurityPerimetersClientListBySubscriptionOptions) *runtime.Pager[SecurityPerimetersClientListBySubscriptionResponse]`
- New function `*SecurityPerimetersClient.NewListPager(string, *SecurityPerimetersClientListOptions) *runtime.Pager[SecurityPerimetersClientListResponse]`
- New function `*SecurityPerimetersClient.Patch(context.Context, string, string, UpdateTagsRequest, *SecurityPerimetersClientPatchOptions) (SecurityPerimetersClientPatchResponse, error)`
- New function `*VirtualAppliancesClient.BeginGetBootDiagnosticLogs(context.Context, string, string, VirtualApplianceBootDiagnosticParameters, *VirtualAppliancesClientBeginGetBootDiagnosticLogsOptions) (*runtime.Poller[VirtualAppliancesClientGetBootDiagnosticLogsResponse], error)`
- New function `*VirtualAppliancesClient.BeginReimage(context.Context, string, string, *VirtualAppliancesClientBeginReimageOptions) (*runtime.Poller[VirtualAppliancesClientReimageResponse], error)`
- New function `*VirtualNetworkGatewaysClient.BeginGetResiliencyInformation(context.Context, string, string, *VirtualNetworkGatewaysClientBeginGetResiliencyInformationOptions) (*runtime.Poller[VirtualNetworkGatewaysClientGetResiliencyInformationResponse], error)`
- New function `*VirtualNetworkGatewaysClient.BeginGetRoutesInformation(context.Context, string, string, *VirtualNetworkGatewaysClientBeginGetRoutesInformationOptions) (*runtime.Poller[VirtualNetworkGatewaysClientGetRoutesInformationResponse], error)`
- New function `*VirtualNetworkGatewaysClient.BeginInvokeAbortMigration(context.Context, string, string, *VirtualNetworkGatewaysClientBeginInvokeAbortMigrationOptions) (*runtime.Poller[VirtualNetworkGatewaysClientInvokeAbortMigrationResponse], error)`
- New function `*VirtualNetworkGatewaysClient.BeginInvokeCommitMigration(context.Context, string, string, *VirtualNetworkGatewaysClientBeginInvokeCommitMigrationOptions) (*runtime.Poller[VirtualNetworkGatewaysClientInvokeCommitMigrationResponse], error)`
- New function `*VirtualNetworkGatewaysClient.BeginInvokeExecuteMigration(context.Context, string, string, *VirtualNetworkGatewaysClientBeginInvokeExecuteMigrationOptions) (*runtime.Poller[VirtualNetworkGatewaysClientInvokeExecuteMigrationResponse], error)`
- New function `*VirtualNetworkGatewaysClient.BeginInvokePrepareMigration(context.Context, string, string, VirtualNetworkGatewayMigrationParameters, *VirtualNetworkGatewaysClientBeginInvokePrepareMigrationOptions) (*runtime.Poller[VirtualNetworkGatewaysClientInvokePrepareMigrationResponse], error)`
- New struct `AdvertisedPublicPrefixProperties`
- New struct `CircuitMetadataMap`
- New struct `ConnectivityConfigurationPropertiesConnectivityCapabilities`
- New struct `ErrorAdditionalInfo`
- New struct `ErrorDetail`
- New struct `GatewayResiliencyInformation`
- New struct `GatewayResiliencyRecommendation`
- New struct `GatewayRouteSet`
- New struct `GatewayRouteSetsInformation`
- New struct `ManagedRuleSetRuleGroup`
- New struct `NspAccessRule`
- New struct `NspAccessRuleListResult`
- New struct `NspAccessRuleProperties`
- New struct `NspAssociation`
- New struct `NspAssociationProperties`
- New struct `NspAssociationsListResult`
- New struct `NspLink`
- New struct `NspLinkListResult`
- New struct `NspLinkProperties`
- New struct `NspLinkReference`
- New struct `NspLinkReferenceListResult`
- New struct `NspLinkReferenceProperties`
- New struct `NspLoggingConfiguration`
- New struct `NspLoggingConfigurationListResult`
- New struct `NspLoggingConfigurationProperties`
- New struct `NspProfile`
- New struct `NspProfileListResult`
- New struct `NspProfileProperties`
- New struct `OperationStatusResult`
- New struct `PerimeterAssociableResource`
- New struct `PerimeterAssociableResourceProperties`
- New struct `PerimeterAssociableResourcesListResult`
- New struct `PerimeterBasedAccessRule`
- New struct `ProxyResource`
- New struct `ResiliencyRecommendationComponents`
- New struct `RouteSourceDetails`
- New struct `SecurityPerimeter`
- New struct `SecurityPerimeterListResult`
- New struct `SecurityPerimeterProperties`
- New struct `SecurityPerimeterProxyResource`
- New struct `SecurityPerimeterResource`
- New struct `SecurityPerimeterSystemData`
- New struct `SubscriptionID`
- New struct `TrackedResource`
- New struct `UpdateTagsRequest`
- New struct `VirtualApplianceBootDiagnosticParameters`
- New struct `VirtualApplianceInstanceID`
- New struct `VirtualNetworkGatewayConnectionTunnelProperties`
- New struct `VirtualNetworkGatewayMigrationParameters`
- New struct `VirtualNetworkGatewayMigrationStatus`
- New field `ConnectivityCapabilities` in struct `ConnectivityConfigurationProperties`
- New field `AdvertisedPublicPrefixInfo` in struct `ExpressRouteCircuitPeeringConfig`
- New field `Etag` in struct `IpamPool`
- New field `IfMatch` in struct `IpamPoolsClientBeginCreateOptions`
- New field `IfMatch` in struct `IpamPoolsClientBeginDeleteOptions`
- New field `IfMatch` in struct `IpamPoolsClientUpdateOptions`
- New field `EnableConnectionTracking` in struct `LoadBalancingRulePropertiesFormat`
- New field `ComputedDisabledRules` in struct `ManagedRuleSet`
- New field `PublicIPAddressesV6`, `PublicIPPrefixesV6`, `SourceVirtualNetwork` in struct `NatGatewayPropertiesFormat`
- New field `Etag` in struct `VerifierWorkspace`
- New field `IfMatch` in struct `VerifierWorkspacesClientBeginDeleteOptions`
- New field `IfMatch` in struct `VerifierWorkspacesClientCreateOptions`
- New field `IfMatch` in struct `VerifierWorkspacesClientUpdateOptions`
- New field `TunnelProperties` in struct `VirtualNetworkGatewayConnectionPropertiesFormat`
- New field `EnableHighBandwidthVPNGateway`, `VirtualNetworkGatewayMigrationStatus` in struct `VirtualNetworkGatewayPropertiesFormat`
- New field `DefaultPublicNatGateway` in struct `VirtualNetworkPropertiesFormat`


## 6.2.0 (2024-12-09)
### Features Added

- New value `AddressPrefixTypeNetworkGroup` added to enum type `AddressPrefixType`
- New value `FirewallPolicyIDPSSignatureDirectionFive` added to enum type `FirewallPolicyIDPSSignatureDirection`
- New value `ProvisioningStateCanceled`, `ProvisioningStateCreating` added to enum type `ProvisioningState`
- New enum type `AddressSpaceAggregationOption` with values `AddressSpaceAggregationOptionManual`, `AddressSpaceAggregationOptionNone`
- New enum type `FailoverConnectionStatus` with values `FailoverConnectionStatusConnected`, `FailoverConnectionStatusDisconnected`
- New enum type `FailoverTestStatus` with values `FailoverTestStatusCompleted`, `FailoverTestStatusExpired`, `FailoverTestStatusInvalid`, `FailoverTestStatusNotStarted`, `FailoverTestStatusRunning`, `FailoverTestStatusStartFailed`, `FailoverTestStatusStarting`, `FailoverTestStatusStopFailed`, `FailoverTestStatusStopping`
- New enum type `FailoverTestStatusForSingleTest` with values `FailoverTestStatusForSingleTestCompleted`, `FailoverTestStatusForSingleTestExpired`, `FailoverTestStatusForSingleTestInvalid`, `FailoverTestStatusForSingleTestNotStarted`, `FailoverTestStatusForSingleTestRunning`, `FailoverTestStatusForSingleTestStartFailed`, `FailoverTestStatusForSingleTestStarting`, `FailoverTestStatusForSingleTestStopFailed`, `FailoverTestStatusForSingleTestStopping`
- New enum type `FailoverTestType` with values `FailoverTestTypeAll`, `FailoverTestTypeMultiSiteFailover`, `FailoverTestTypeSingleSiteFailover`
- New enum type `IPType` with values `IPTypeIPv4`, `IPTypeIPv6`
- New enum type `NetworkProtocol` with values `NetworkProtocolAny`, `NetworkProtocolICMP`, `NetworkProtocolTCP`, `NetworkProtocolUDP`
- New function `*ClientFactory.NewIpamPoolsClient() *IpamPoolsClient`
- New function `*ClientFactory.NewReachabilityAnalysisIntentsClient() *ReachabilityAnalysisIntentsClient`
- New function `*ClientFactory.NewReachabilityAnalysisRunsClient() *ReachabilityAnalysisRunsClient`
- New function `*ClientFactory.NewStaticCidrsClient() *StaticCidrsClient`
- New function `*ClientFactory.NewVerifierWorkspacesClient() *VerifierWorkspacesClient`
- New function `NewIpamPoolsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*IpamPoolsClient, error)`
- New function `*IpamPoolsClient.BeginCreate(context.Context, string, string, string, IpamPool, *IpamPoolsClientBeginCreateOptions) (*runtime.Poller[IpamPoolsClientCreateResponse], error)`
- New function `*IpamPoolsClient.BeginDelete(context.Context, string, string, string, *IpamPoolsClientBeginDeleteOptions) (*runtime.Poller[IpamPoolsClientDeleteResponse], error)`
- New function `*IpamPoolsClient.Get(context.Context, string, string, string, *IpamPoolsClientGetOptions) (IpamPoolsClientGetResponse, error)`
- New function `*IpamPoolsClient.GetPoolUsage(context.Context, string, string, string, *IpamPoolsClientGetPoolUsageOptions) (IpamPoolsClientGetPoolUsageResponse, error)`
- New function `*IpamPoolsClient.NewListAssociatedResourcesPager(string, string, string, *IpamPoolsClientListAssociatedResourcesOptions) *runtime.Pager[IpamPoolsClientListAssociatedResourcesResponse]`
- New function `*IpamPoolsClient.NewListPager(string, string, *IpamPoolsClientListOptions) *runtime.Pager[IpamPoolsClientListResponse]`
- New function `*IpamPoolsClient.Update(context.Context, string, string, string, *IpamPoolsClientUpdateOptions) (IpamPoolsClientUpdateResponse, error)`
- New function `*LoadBalancerLoadBalancingRulesClient.BeginHealth(context.Context, string, string, string, *LoadBalancerLoadBalancingRulesClientBeginHealthOptions) (*runtime.Poller[LoadBalancerLoadBalancingRulesClientHealthResponse], error)`
- New function `NewReachabilityAnalysisIntentsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*ReachabilityAnalysisIntentsClient, error)`
- New function `*ReachabilityAnalysisIntentsClient.Create(context.Context, string, string, string, string, ReachabilityAnalysisIntent, *ReachabilityAnalysisIntentsClientCreateOptions) (ReachabilityAnalysisIntentsClientCreateResponse, error)`
- New function `*ReachabilityAnalysisIntentsClient.Delete(context.Context, string, string, string, string, *ReachabilityAnalysisIntentsClientDeleteOptions) (ReachabilityAnalysisIntentsClientDeleteResponse, error)`
- New function `*ReachabilityAnalysisIntentsClient.Get(context.Context, string, string, string, string, *ReachabilityAnalysisIntentsClientGetOptions) (ReachabilityAnalysisIntentsClientGetResponse, error)`
- New function `*ReachabilityAnalysisIntentsClient.NewListPager(string, string, string, *ReachabilityAnalysisIntentsClientListOptions) *runtime.Pager[ReachabilityAnalysisIntentsClientListResponse]`
- New function `NewReachabilityAnalysisRunsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*ReachabilityAnalysisRunsClient, error)`
- New function `*ReachabilityAnalysisRunsClient.Create(context.Context, string, string, string, string, ReachabilityAnalysisRun, *ReachabilityAnalysisRunsClientCreateOptions) (ReachabilityAnalysisRunsClientCreateResponse, error)`
- New function `*ReachabilityAnalysisRunsClient.BeginDelete(context.Context, string, string, string, string, *ReachabilityAnalysisRunsClientBeginDeleteOptions) (*runtime.Poller[ReachabilityAnalysisRunsClientDeleteResponse], error)`
- New function `*ReachabilityAnalysisRunsClient.Get(context.Context, string, string, string, string, *ReachabilityAnalysisRunsClientGetOptions) (ReachabilityAnalysisRunsClientGetResponse, error)`
- New function `*ReachabilityAnalysisRunsClient.NewListPager(string, string, string, *ReachabilityAnalysisRunsClientListOptions) *runtime.Pager[ReachabilityAnalysisRunsClientListResponse]`
- New function `NewStaticCidrsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*StaticCidrsClient, error)`
- New function `*StaticCidrsClient.Create(context.Context, string, string, string, string, *StaticCidrsClientCreateOptions) (StaticCidrsClientCreateResponse, error)`
- New function `*StaticCidrsClient.BeginDelete(context.Context, string, string, string, string, *StaticCidrsClientBeginDeleteOptions) (*runtime.Poller[StaticCidrsClientDeleteResponse], error)`
- New function `*StaticCidrsClient.Get(context.Context, string, string, string, string, *StaticCidrsClientGetOptions) (StaticCidrsClientGetResponse, error)`
- New function `*StaticCidrsClient.NewListPager(string, string, string, *StaticCidrsClientListOptions) *runtime.Pager[StaticCidrsClientListResponse]`
- New function `NewVerifierWorkspacesClient(string, azcore.TokenCredential, *arm.ClientOptions) (*VerifierWorkspacesClient, error)`
- New function `*VerifierWorkspacesClient.Create(context.Context, string, string, string, VerifierWorkspace, *VerifierWorkspacesClientCreateOptions) (VerifierWorkspacesClientCreateResponse, error)`
- New function `*VerifierWorkspacesClient.BeginDelete(context.Context, string, string, string, *VerifierWorkspacesClientBeginDeleteOptions) (*runtime.Poller[VerifierWorkspacesClientDeleteResponse], error)`
- New function `*VerifierWorkspacesClient.Get(context.Context, string, string, string, *VerifierWorkspacesClientGetOptions) (VerifierWorkspacesClientGetResponse, error)`
- New function `*VerifierWorkspacesClient.NewListPager(string, string, *VerifierWorkspacesClientListOptions) *runtime.Pager[VerifierWorkspacesClientListResponse]`
- New function `*VerifierWorkspacesClient.Update(context.Context, string, string, string, *VerifierWorkspacesClientUpdateOptions) (VerifierWorkspacesClientUpdateResponse, error)`
- New function `*VirtualNetworkGatewaysClient.BeginGetFailoverAllTestDetails(context.Context, string, string, string, bool, *VirtualNetworkGatewaysClientBeginGetFailoverAllTestDetailsOptions) (*runtime.Poller[VirtualNetworkGatewaysClientGetFailoverAllTestDetailsResponse], error)`
- New function `*VirtualNetworkGatewaysClient.BeginGetFailoverSingleTestDetails(context.Context, string, string, string, string, *VirtualNetworkGatewaysClientBeginGetFailoverSingleTestDetailsOptions) (*runtime.Poller[VirtualNetworkGatewaysClientGetFailoverSingleTestDetailsResponse], error)`
- New function `*VirtualNetworkGatewaysClient.BeginStartExpressRouteSiteFailoverSimulation(context.Context, string, string, string, *VirtualNetworkGatewaysClientBeginStartExpressRouteSiteFailoverSimulationOptions) (*runtime.Poller[VirtualNetworkGatewaysClientStartExpressRouteSiteFailoverSimulationResponse], error)`
- New function `*VirtualNetworkGatewaysClient.BeginStopExpressRouteSiteFailoverSimulation(context.Context, string, string, ExpressRouteFailoverStopAPIParameters, *VirtualNetworkGatewaysClientBeginStopExpressRouteSiteFailoverSimulationOptions) (*runtime.Poller[VirtualNetworkGatewaysClientStopExpressRouteSiteFailoverSimulationResponse], error)`
- New struct `CommonErrorAdditionalInfo`
- New struct `CommonErrorDetail`
- New struct `CommonErrorResponse`
- New struct `CommonProxyResource`
- New struct `CommonResource`
- New struct `CommonTrackedResource`
- New struct `ExpressRouteFailoverCircuitResourceDetails`
- New struct `ExpressRouteFailoverConnectionResourceDetails`
- New struct `ExpressRouteFailoverRedundantRoute`
- New struct `ExpressRouteFailoverSingleTestDetails`
- New struct `ExpressRouteFailoverStopAPIParameters`
- New struct `ExpressRouteFailoverTestDetails`
- New struct `FailoverConnectionDetails`
- New struct `IPTraffic`
- New struct `IntentContent`
- New struct `IpamPool`
- New struct `IpamPoolList`
- New struct `IpamPoolPrefixAllocation`
- New struct `IpamPoolPrefixAllocationPool`
- New struct `IpamPoolProperties`
- New struct `IpamPoolUpdate`
- New struct `IpamPoolUpdateProperties`
- New struct `LoadBalancerHealthPerRule`
- New struct `LoadBalancerHealthPerRulePerBackendAddress`
- New struct `PoolAssociation`
- New struct `PoolAssociationList`
- New struct `PoolUsage`
- New struct `ReachabilityAnalysisIntent`
- New struct `ReachabilityAnalysisIntentListResult`
- New struct `ReachabilityAnalysisIntentProperties`
- New struct `ReachabilityAnalysisRun`
- New struct `ReachabilityAnalysisRunListResult`
- New struct `ReachabilityAnalysisRunProperties`
- New struct `ResourceBasics`
- New struct `StaticCidr`
- New struct `StaticCidrList`
- New struct `StaticCidrProperties`
- New struct `VerifierWorkspace`
- New struct `VerifierWorkspaceListResult`
- New struct `VerifierWorkspaceProperties`
- New struct `VerifierWorkspaceUpdate`
- New struct `VerifierWorkspaceUpdateProperties`
- New field `IpamPoolPrefixAllocations` in struct `AddressSpace`
- New field `EnablePrivateOnlyBastion` in struct `BastionHostPropertiesFormat`
- New field `DefaultOutboundConnectivityEnabled` in struct `InterfacePropertiesFormat`
- New field `NetworkGroupAddressSpaceAggregationOption` in struct `SecurityAdminConfigurationPropertiesFormat`
- New field `IpamPoolPrefixAllocations` in struct `SubnetPropertiesFormat`


## 6.1.0 (2024-09-24)
### Features Added

- New value `ConfigurationTypeRouting`, `ConfigurationTypeSecurityUser` added to enum type `ConfigurationType`
- New enum type `ApplicationGatewayWafRuleSensitivityTypes` with values `ApplicationGatewayWafRuleSensitivityTypesHigh`, `ApplicationGatewayWafRuleSensitivityTypesLow`, `ApplicationGatewayWafRuleSensitivityTypesMedium`, `ApplicationGatewayWafRuleSensitivityTypesNone`
- New enum type `DisableBgpRoutePropagation` with values `DisableBgpRoutePropagationFalse`, `DisableBgpRoutePropagationTrue`
- New enum type `ExceptionEntryMatchVariable` with values `ExceptionEntryMatchVariableRemoteAddr`, `ExceptionEntryMatchVariableRequestHeader`, `ExceptionEntryMatchVariableRequestURI`
- New enum type `ExceptionEntrySelectorMatchOperator` with values `ExceptionEntrySelectorMatchOperatorContains`, `ExceptionEntrySelectorMatchOperatorEndsWith`, `ExceptionEntrySelectorMatchOperatorEquals`, `ExceptionEntrySelectorMatchOperatorStartsWith`
- New enum type `ExceptionEntryValueMatchOperator` with values `ExceptionEntryValueMatchOperatorContains`, `ExceptionEntryValueMatchOperatorEndsWith`, `ExceptionEntryValueMatchOperatorEquals`, `ExceptionEntryValueMatchOperatorIPMatch`, `ExceptionEntryValueMatchOperatorStartsWith`
- New enum type `GroupMemberType` with values `GroupMemberTypeSubnet`, `GroupMemberTypeVirtualNetwork`
- New enum type `PrivateEndpointVNetPolicies` with values `PrivateEndpointVNetPoliciesBasic`, `PrivateEndpointVNetPoliciesDisabled`
- New enum type `ResiliencyModel` with values `ResiliencyModelMultiHomed`, `ResiliencyModelSingleHomed`
- New enum type `RoutingRuleDestinationType` with values `RoutingRuleDestinationTypeAddressPrefix`, `RoutingRuleDestinationTypeServiceTag`
- New enum type `RoutingRuleNextHopType` with values `RoutingRuleNextHopTypeInternet`, `RoutingRuleNextHopTypeNoNextHop`, `RoutingRuleNextHopTypeVirtualAppliance`, `RoutingRuleNextHopTypeVirtualNetworkGateway`, `RoutingRuleNextHopTypeVnetLocal`
- New enum type `SensitivityType` with values `SensitivityTypeHigh`, `SensitivityTypeLow`, `SensitivityTypeMedium`, `SensitivityTypeNone`
- New function `*ClientFactory.NewManagerRoutingConfigurationsClient() *ManagerRoutingConfigurationsClient`
- New function `*ClientFactory.NewRoutingRuleCollectionsClient() *RoutingRuleCollectionsClient`
- New function `*ClientFactory.NewRoutingRulesClient() *RoutingRulesClient`
- New function `*ClientFactory.NewSecurityUserConfigurationsClient() *SecurityUserConfigurationsClient`
- New function `*ClientFactory.NewSecurityUserRuleCollectionsClient() *SecurityUserRuleCollectionsClient`
- New function `*ClientFactory.NewSecurityUserRulesClient() *SecurityUserRulesClient`
- New function `NewManagerRoutingConfigurationsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*ManagerRoutingConfigurationsClient, error)`
- New function `*ManagerRoutingConfigurationsClient.CreateOrUpdate(context.Context, string, string, string, ManagerRoutingConfiguration, *ManagerRoutingConfigurationsClientCreateOrUpdateOptions) (ManagerRoutingConfigurationsClientCreateOrUpdateResponse, error)`
- New function `*ManagerRoutingConfigurationsClient.BeginDelete(context.Context, string, string, string, *ManagerRoutingConfigurationsClientBeginDeleteOptions) (*runtime.Poller[ManagerRoutingConfigurationsClientDeleteResponse], error)`
- New function `*ManagerRoutingConfigurationsClient.Get(context.Context, string, string, string, *ManagerRoutingConfigurationsClientGetOptions) (ManagerRoutingConfigurationsClientGetResponse, error)`
- New function `*ManagerRoutingConfigurationsClient.NewListPager(string, string, *ManagerRoutingConfigurationsClientListOptions) *runtime.Pager[ManagerRoutingConfigurationsClientListResponse]`
- New function `NewRoutingRuleCollectionsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*RoutingRuleCollectionsClient, error)`
- New function `*RoutingRuleCollectionsClient.CreateOrUpdate(context.Context, string, string, string, string, RoutingRuleCollection, *RoutingRuleCollectionsClientCreateOrUpdateOptions) (RoutingRuleCollectionsClientCreateOrUpdateResponse, error)`
- New function `*RoutingRuleCollectionsClient.BeginDelete(context.Context, string, string, string, string, *RoutingRuleCollectionsClientBeginDeleteOptions) (*runtime.Poller[RoutingRuleCollectionsClientDeleteResponse], error)`
- New function `*RoutingRuleCollectionsClient.Get(context.Context, string, string, string, string, *RoutingRuleCollectionsClientGetOptions) (RoutingRuleCollectionsClientGetResponse, error)`
- New function `*RoutingRuleCollectionsClient.NewListPager(string, string, string, *RoutingRuleCollectionsClientListOptions) *runtime.Pager[RoutingRuleCollectionsClientListResponse]`
- New function `NewRoutingRulesClient(string, azcore.TokenCredential, *arm.ClientOptions) (*RoutingRulesClient, error)`
- New function `*RoutingRulesClient.CreateOrUpdate(context.Context, string, string, string, string, string, RoutingRule, *RoutingRulesClientCreateOrUpdateOptions) (RoutingRulesClientCreateOrUpdateResponse, error)`
- New function `*RoutingRulesClient.BeginDelete(context.Context, string, string, string, string, string, *RoutingRulesClientBeginDeleteOptions) (*runtime.Poller[RoutingRulesClientDeleteResponse], error)`
- New function `*RoutingRulesClient.Get(context.Context, string, string, string, string, string, *RoutingRulesClientGetOptions) (RoutingRulesClientGetResponse, error)`
- New function `*RoutingRulesClient.NewListPager(string, string, string, string, *RoutingRulesClientListOptions) *runtime.Pager[RoutingRulesClientListResponse]`
- New function `NewSecurityUserConfigurationsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*SecurityUserConfigurationsClient, error)`
- New function `*SecurityUserConfigurationsClient.CreateOrUpdate(context.Context, string, string, string, SecurityUserConfiguration, *SecurityUserConfigurationsClientCreateOrUpdateOptions) (SecurityUserConfigurationsClientCreateOrUpdateResponse, error)`
- New function `*SecurityUserConfigurationsClient.BeginDelete(context.Context, string, string, string, *SecurityUserConfigurationsClientBeginDeleteOptions) (*runtime.Poller[SecurityUserConfigurationsClientDeleteResponse], error)`
- New function `*SecurityUserConfigurationsClient.Get(context.Context, string, string, string, *SecurityUserConfigurationsClientGetOptions) (SecurityUserConfigurationsClientGetResponse, error)`
- New function `*SecurityUserConfigurationsClient.NewListPager(string, string, *SecurityUserConfigurationsClientListOptions) *runtime.Pager[SecurityUserConfigurationsClientListResponse]`
- New function `NewSecurityUserRuleCollectionsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*SecurityUserRuleCollectionsClient, error)`
- New function `*SecurityUserRuleCollectionsClient.CreateOrUpdate(context.Context, string, string, string, string, SecurityUserRuleCollection, *SecurityUserRuleCollectionsClientCreateOrUpdateOptions) (SecurityUserRuleCollectionsClientCreateOrUpdateResponse, error)`
- New function `*SecurityUserRuleCollectionsClient.BeginDelete(context.Context, string, string, string, string, *SecurityUserRuleCollectionsClientBeginDeleteOptions) (*runtime.Poller[SecurityUserRuleCollectionsClientDeleteResponse], error)`
- New function `*SecurityUserRuleCollectionsClient.Get(context.Context, string, string, string, string, *SecurityUserRuleCollectionsClientGetOptions) (SecurityUserRuleCollectionsClientGetResponse, error)`
- New function `*SecurityUserRuleCollectionsClient.NewListPager(string, string, string, *SecurityUserRuleCollectionsClientListOptions) *runtime.Pager[SecurityUserRuleCollectionsClientListResponse]`
- New function `NewSecurityUserRulesClient(string, azcore.TokenCredential, *arm.ClientOptions) (*SecurityUserRulesClient, error)`
- New function `*SecurityUserRulesClient.CreateOrUpdate(context.Context, string, string, string, string, string, SecurityUserRule, *SecurityUserRulesClientCreateOrUpdateOptions) (SecurityUserRulesClientCreateOrUpdateResponse, error)`
- New function `*SecurityUserRulesClient.BeginDelete(context.Context, string, string, string, string, string, *SecurityUserRulesClientBeginDeleteOptions) (*runtime.Poller[SecurityUserRulesClientDeleteResponse], error)`
- New function `*SecurityUserRulesClient.Get(context.Context, string, string, string, string, string, *SecurityUserRulesClientGetOptions) (SecurityUserRulesClientGetResponse, error)`
- New function `*SecurityUserRulesClient.NewListPager(string, string, string, string, *SecurityUserRulesClientListOptions) *runtime.Pager[SecurityUserRulesClientListResponse]`
- New function `*VPNLinkConnectionsClient.NewGetAllSharedKeysPager(string, string, string, string, *VPNLinkConnectionsClientGetAllSharedKeysOptions) *runtime.Pager[VPNLinkConnectionsClientGetAllSharedKeysResponse]`
- New function `*VPNLinkConnectionsClient.GetDefaultSharedKey(context.Context, string, string, string, string, *VPNLinkConnectionsClientGetDefaultSharedKeyOptions) (VPNLinkConnectionsClientGetDefaultSharedKeyResponse, error)`
- New function `*VPNLinkConnectionsClient.ListDefaultSharedKey(context.Context, string, string, string, string, *VPNLinkConnectionsClientListDefaultSharedKeyOptions) (VPNLinkConnectionsClientListDefaultSharedKeyResponse, error)`
- New function `*VPNLinkConnectionsClient.BeginSetOrInitDefaultSharedKey(context.Context, string, string, string, string, ConnectionSharedKeyResult, *VPNLinkConnectionsClientBeginSetOrInitDefaultSharedKeyOptions) (*runtime.Poller[VPNLinkConnectionsClientSetOrInitDefaultSharedKeyResponse], error)`
- New struct `ApplicationGatewayForContainersReferenceDefinition`
- New struct `AzureFirewallAutoscaleConfiguration`
- New struct `ConnectionSharedKeyResult`
- New struct `ConnectionSharedKeyResultList`
- New struct `ExceptionEntry`
- New struct `ManagerRoutingConfiguration`
- New struct `ManagerRoutingConfigurationListResult`
- New struct `ManagerRoutingConfigurationPropertiesFormat`
- New struct `ManagerRoutingGroupItem`
- New struct `RoutingRule`
- New struct `RoutingRuleCollection`
- New struct `RoutingRuleCollectionListResult`
- New struct `RoutingRuleCollectionPropertiesFormat`
- New struct `RoutingRuleListResult`
- New struct `RoutingRuleNextHop`
- New struct `RoutingRulePropertiesFormat`
- New struct `RoutingRuleRouteDestination`
- New struct `SecurityUserConfiguration`
- New struct `SecurityUserConfigurationListResult`
- New struct `SecurityUserConfigurationPropertiesFormat`
- New struct `SecurityUserGroupItem`
- New struct `SecurityUserRule`
- New struct `SecurityUserRuleCollection`
- New struct `SecurityUserRuleCollectionListResult`
- New struct `SecurityUserRuleCollectionPropertiesFormat`
- New struct `SecurityUserRuleListResult`
- New struct `SecurityUserRulePropertiesFormat`
- New struct `SharedKeyProperties`
- New field `Sensitivity` in struct `ApplicationGatewayFirewallRule`
- New field `AutoscaleConfiguration` in struct `AzureFirewallPropertiesFormat`
- New field `EnabledFilteringCriteria` in struct `FlowLogProperties`
- New field `EnabledFilteringCriteria` in struct `FlowLogPropertiesFormat`
- New field `MemberType` in struct `GroupProperties`
- New field `Sensitivity` in struct `ManagedRuleOverride`
- New field `Exceptions` in struct `ManagedRulesDefinition`
- New field `DestinationIPAddress` in struct `PrivateLinkServiceProperties`
- New field `ResiliencyModel` in struct `VirtualNetworkGatewayPropertiesFormat`
- New field `PrivateEndpointVNetPolicies` in struct `VirtualNetworkPropertiesFormat`
- New field `ApplicationGatewayForContainers` in struct `WebApplicationFirewallPolicyPropertiesFormat`


## 6.0.0 (2024-07-25)
### Breaking Changes

- Struct `FirewallPacketCaptureParametersFormat` has been removed
- Field `ID`, `Properties` of struct `FirewallPacketCaptureParameters` has been removed

### Features Added

- New value `BastionHostSKUNamePremium` added to enum type `BastionHostSKUName`
- New enum type `ProbeNoHealthyBackendsBehavior` with values `ProbeNoHealthyBackendsBehaviorAllProbedDown`, `ProbeNoHealthyBackendsBehaviorAllProbedUp`
- New function `*InboundSecurityRuleClient.Get(context.Context, string, string, string, *InboundSecurityRuleClientGetOptions) (InboundSecurityRuleClientGetResponse, error)`
- New field `ConnectionResourceURI` in struct `AuthorizationPropertiesFormat`
- New field `EnableSessionRecording` in struct `BastionHostPropertiesFormat`
- New field `Filter` in struct `ExpressRouteCrossConnectionsClientListOptions`
- New field `DurationInSeconds`, `FileName`, `Filters`, `Flags`, `NumberOfPacketsToCapture`, `Protocol`, `SasURL` in struct `FirewallPacketCaptureParameters`
- New field `Identity` in struct `FlowLog`
- New field `Identity` in struct `FlowLogInformation`
- New field `NoHealthyBackendsBehavior` in struct `ProbePropertiesFormat`
- New field `NetworkIdentifier` in struct `ServiceEndpointPropertiesFormat`
- New field `Identity` in struct `VirtualNetworkGateway`


## 5.2.0 (2024-06-21)
### Features Added

- New value `EndpointTypeAzureArcNetwork` added to enum type `EndpointType`
- New enum type `ApplicationGatewaySKUFamily` with values `ApplicationGatewaySKUFamilyGeneration1`, `ApplicationGatewaySKUFamilyGeneration2`
- New enum type `InboundSecurityRuleType` with values `InboundSecurityRuleTypeAutoExpire`, `InboundSecurityRuleTypePermanent`
- New enum type `NicTypeInRequest` with values `NicTypeInRequestPrivateNic`, `NicTypeInRequestPublicNic`
- New enum type `NicTypeInResponse` with values `NicTypeInResponseAdditionalNic`, `NicTypeInResponsePrivateNic`, `NicTypeInResponsePublicNic`
- New enum type `SharingScope` with values `SharingScopeDelegatedServices`, `SharingScopeTenant`
- New function `*ClientFactory.NewFirewallPolicyDeploymentsClient() *FirewallPolicyDeploymentsClient`
- New function `*ClientFactory.NewFirewallPolicyDraftsClient() *FirewallPolicyDraftsClient`
- New function `*ClientFactory.NewFirewallPolicyRuleCollectionGroupDraftsClient() *FirewallPolicyRuleCollectionGroupDraftsClient`
- New function `NewFirewallPolicyDeploymentsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*FirewallPolicyDeploymentsClient, error)`
- New function `*FirewallPolicyDeploymentsClient.BeginDeploy(context.Context, string, string, *FirewallPolicyDeploymentsClientBeginDeployOptions) (*runtime.Poller[FirewallPolicyDeploymentsClientDeployResponse], error)`
- New function `NewFirewallPolicyDraftsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*FirewallPolicyDraftsClient, error)`
- New function `*FirewallPolicyDraftsClient.CreateOrUpdate(context.Context, string, string, FirewallPolicyDraft, *FirewallPolicyDraftsClientCreateOrUpdateOptions) (FirewallPolicyDraftsClientCreateOrUpdateResponse, error)`
- New function `*FirewallPolicyDraftsClient.Delete(context.Context, string, string, *FirewallPolicyDraftsClientDeleteOptions) (FirewallPolicyDraftsClientDeleteResponse, error)`
- New function `*FirewallPolicyDraftsClient.Get(context.Context, string, string, *FirewallPolicyDraftsClientGetOptions) (FirewallPolicyDraftsClientGetResponse, error)`
- New function `NewFirewallPolicyRuleCollectionGroupDraftsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*FirewallPolicyRuleCollectionGroupDraftsClient, error)`
- New function `*FirewallPolicyRuleCollectionGroupDraftsClient.CreateOrUpdate(context.Context, string, string, string, FirewallPolicyRuleCollectionGroupDraft, *FirewallPolicyRuleCollectionGroupDraftsClientCreateOrUpdateOptions) (FirewallPolicyRuleCollectionGroupDraftsClientCreateOrUpdateResponse, error)`
- New function `*FirewallPolicyRuleCollectionGroupDraftsClient.Delete(context.Context, string, string, string, *FirewallPolicyRuleCollectionGroupDraftsClientDeleteOptions) (FirewallPolicyRuleCollectionGroupDraftsClientDeleteResponse, error)`
- New function `*FirewallPolicyRuleCollectionGroupDraftsClient.Get(context.Context, string, string, string, *FirewallPolicyRuleCollectionGroupDraftsClientGetOptions) (FirewallPolicyRuleCollectionGroupDraftsClientGetResponse, error)`
- New function `*VirtualAppliancesClient.BeginRestart(context.Context, string, string, *VirtualAppliancesClientBeginRestartOptions) (*runtime.Poller[VirtualAppliancesClientRestartResponse], error)`
- New struct `ConnectionMonitorEndpointLocationDetails`
- New struct `FirewallPolicyDraft`
- New struct `FirewallPolicyDraftProperties`
- New struct `FirewallPolicyRuleCollectionGroupDraft`
- New struct `FirewallPolicyRuleCollectionGroupDraftProperties`
- New struct `HeaderValueMatcher`
- New struct `PacketCaptureSettings`
- New struct `VirtualApplianceIPConfiguration`
- New struct `VirtualApplianceIPConfigurationProperties`
- New struct `VirtualApplianceInstanceIDs`
- New struct `VirtualApplianceNetworkInterfaceConfiguration`
- New struct `VirtualApplianceNetworkInterfaceConfigurationProperties`
- New struct `VirtualAppliancePropertiesFormatNetworkProfile`
- New field `HeaderValueMatcher` in struct `ApplicationGatewayHeaderConfiguration`
- New field `Family` in struct `ApplicationGatewaySKU`
- New field `LocationDetails`, `SubscriptionID` in struct `ConnectionMonitorEndpoint`
- New field `EnableDirectPortRateLimit` in struct `ExpressRouteCircuitPropertiesFormat`
- New field `RuleType` in struct `InboundSecurityRuleProperties`
- New field `AppliesOn`, `DestinationPortRanges`, `Name` in struct `InboundSecurityRules`
- New field `PrivateIPAddressPrefixLength` in struct `InterfaceIPConfigurationPropertiesFormat`
- New field `CaptureSettings`, `ContinuousCapture` in struct `PacketCaptureParameters`
- New field `CaptureSettings`, `ContinuousCapture` in struct `PacketCaptureResultProperties`
- New field `LocalPath` in struct `PacketCaptureStorageLocation`
- New field `JsChallengeCookieExpirationInMins` in struct `PolicySettings`
- New field `SharingScope` in struct `SubnetPropertiesFormat`
- New field `DpdTimeoutSeconds` in struct `VPNSiteLinkConnectionProperties`
- New field `NicType` in struct `VirtualApplianceNicProperties`
- New field `NetworkProfile` in struct `VirtualAppliancePropertiesFormat`
- New field `EnableOnlyIPv6Peering`, `LocalAddressSpace`, `LocalSubnetNames`, `LocalVirtualNetworkAddressSpace`, `PeerCompleteVnets`, `RemoteSubnetNames` in struct `VirtualNetworkPeeringPropertiesFormat`


## 5.1.1 (2024-04-02)
### Other Changes

- upgrade azcore version


## 5.1.0 (2024-02-23)
### Features Added

- New value `VirtualNetworkPrivateEndpointNetworkPoliciesNetworkSecurityGroupEnabled`, `VirtualNetworkPrivateEndpointNetworkPoliciesRouteTableEnabled` added to enum type `VirtualNetworkPrivateEndpointNetworkPolicies`
- New field `Zones` in struct `BastionHost`


## 5.0.0 (2023-12-22)
### Breaking Changes

- Type of `VirtualApplianceConnectionProperties.RoutingConfiguration` has been changed from `*RoutingConfigurationNfv` to `*RoutingConfiguration`
- Struct `PropagatedRouteTableNfv` has been removed
- Struct `RoutingConfigurationNfv` has been removed
- Struct `RoutingConfigurationNfvSubResource` has been removed

### Features Added

- New value `ActionTypeJSChallenge` added to enum type `ActionType`
- New value `BastionHostSKUNameDeveloper` added to enum type `BastionHostSKUName`
- New value `FirewallPolicyIDPSSignatureDirectionFour`, `FirewallPolicyIDPSSignatureDirectionThree` added to enum type `FirewallPolicyIDPSSignatureDirection`
- New value `VirtualNetworkGatewaySKUNameErGwScale` added to enum type `VirtualNetworkGatewaySKUName`
- New value `VirtualNetworkGatewaySKUTierErGwScale` added to enum type `VirtualNetworkGatewaySKUTier`
- New value `WebApplicationFirewallActionJSChallenge` added to enum type `WebApplicationFirewallAction`
- New enum type `FirewallPolicyIntrusionDetectionProfileType` with values `FirewallPolicyIntrusionDetectionProfileTypeAdvanced`, `FirewallPolicyIntrusionDetectionProfileTypeBasic`, `FirewallPolicyIntrusionDetectionProfileTypeExtended`, `FirewallPolicyIntrusionDetectionProfileTypeStandard`
- New function `*ManagementClient.BeginDeleteBastionShareableLinkByToken(context.Context, string, string, BastionShareableLinkTokenListRequest, *ManagementClientBeginDeleteBastionShareableLinkByTokenOptions) (*runtime.Poller[ManagementClientDeleteBastionShareableLinkByTokenResponse], error)`
- New struct `BastionShareableLinkTokenListRequest`
- New struct `InternetIngressPublicIPsProperties`
- New field `HostNames` in struct `ApplicationGatewayListenerPropertiesFormat`
- New field `Profile` in struct `FirewallPolicyIntrusionDetection`
- New field `InternetIngressPublicIPs` in struct `VirtualAppliancePropertiesFormat`


## 4.3.0 (2023-11-24)
### Features Added

- Support for test fakes and OpenTelemetry trace spans.


## 4.3.0-beta.1 (2023-10-09)
### Features Added

- Support for test fakes and OpenTelemetry trace spans.

## 4.2.0 (2023-09-22)
### Features Added

- New struct `BastionHostPropertiesFormatNetworkACLs`
- New struct `IPRule`
- New struct `VirtualNetworkGatewayAutoScaleBounds`
- New struct `VirtualNetworkGatewayAutoScaleConfiguration`
- New field `NetworkACLs`, `VirtualNetwork` in struct `BastionHostPropertiesFormat`
- New field `Size` in struct `FirewallPolicyPropertiesFormat`
- New field `Size` in struct `FirewallPolicyRuleCollectionGroupProperties`
- New field `DefaultOutboundAccess` in struct `SubnetPropertiesFormat`
- New field `AutoScaleConfiguration` in struct `VirtualNetworkGatewayPropertiesFormat`


## 4.1.0 (2023-08-25)
### Features Added

- New value `ApplicationGatewaySKUNameBasic` added to enum type `ApplicationGatewaySKUName`
- New value `ApplicationGatewayTierBasic` added to enum type `ApplicationGatewayTier`
- New enum type `SyncMode` with values `SyncModeAutomatic`, `SyncModeManual`
- New function `*LoadBalancersClient.MigrateToIPBased(context.Context, string, string, *LoadBalancersClientMigrateToIPBasedOptions) (LoadBalancersClientMigrateToIPBasedResponse, error)`
- New struct `MigrateLoadBalancerToIPBasedRequest`
- New struct `MigratedPools`
- New field `SyncMode` in struct `BackendAddressPoolPropertiesFormat`


## 4.0.0 (2023-07-11)
### Breaking Changes

- `ApplicationGatewayCustomErrorStatusCodeHTTPStatus499` from enum `ApplicationGatewayCustomErrorStatusCode` has been removed

### Features Added

- New enum type `AdminState` with values `AdminStateDisabled`, `AdminStateEnabled`
- New field `ResourceGUID` in struct `AdminPropertiesFormat`
- New field `ResourceGUID` in struct `AdminRuleCollectionPropertiesFormat`
- New field `DefaultPredefinedSSLPolicy` in struct `ApplicationGatewayPropertiesFormat`
- New field `ResourceGUID` in struct `ConnectivityConfigurationProperties`
- New field `ResourceGUID` in struct `DefaultAdminPropertiesFormat`
- New field `ResourceGUID` in struct `GroupProperties`
- New field `ResourceGUID` in struct `ManagerProperties`
- New field `ResourceGUID` in struct `SecurityAdminConfigurationPropertiesFormat`
- New field `AdminState` in struct `VirtualNetworkGatewayPropertiesFormat`


## 3.0.0 (2023-05-26)
### Breaking Changes

- Type of `EffectiveRouteMapRoute.Prefix` has been changed from `[]*string` to `*string`
- `LoadBalancerBackendAddressAdminStateDrain` from enum `LoadBalancerBackendAddressAdminState` has been removed
- Struct `PeerRouteList` has been removed
- Field `PeerRouteList` of struct `VirtualHubBgpConnectionsClientListAdvertisedRoutesResponse` has been removed
- Field `PeerRouteList` of struct `VirtualHubBgpConnectionsClientListLearnedRoutesResponse` has been removed

### Features Added

- New value `NetworkInterfaceAuxiliaryModeAcceleratedConnections` added to enum type `NetworkInterfaceAuxiliaryMode`
- New value `WebApplicationFirewallRuleTypeRateLimitRule` added to enum type `WebApplicationFirewallRuleType`
- New enum type `ApplicationGatewayFirewallRateLimitDuration` with values `ApplicationGatewayFirewallRateLimitDurationFiveMins`, `ApplicationGatewayFirewallRateLimitDurationOneMin`
- New enum type `ApplicationGatewayFirewallUserSessionVariable` with values `ApplicationGatewayFirewallUserSessionVariableClientAddr`, `ApplicationGatewayFirewallUserSessionVariableGeoLocation`, `ApplicationGatewayFirewallUserSessionVariableNone`
- New enum type `AzureFirewallPacketCaptureFlagsType` with values `AzureFirewallPacketCaptureFlagsTypeAck`, `AzureFirewallPacketCaptureFlagsTypeFin`, `AzureFirewallPacketCaptureFlagsTypePush`, `AzureFirewallPacketCaptureFlagsTypeRst`, `AzureFirewallPacketCaptureFlagsTypeSyn`, `AzureFirewallPacketCaptureFlagsTypeUrg`
- New enum type `NetworkInterfaceAuxiliarySKU` with values `NetworkInterfaceAuxiliarySKUA1`, `NetworkInterfaceAuxiliarySKUA2`, `NetworkInterfaceAuxiliarySKUA4`, `NetworkInterfaceAuxiliarySKUA8`, `NetworkInterfaceAuxiliarySKUNone`
- New enum type `PublicIPAddressDNSSettingsDomainNameLabelScope` with values `PublicIPAddressDNSSettingsDomainNameLabelScopeNoReuse`, `PublicIPAddressDNSSettingsDomainNameLabelScopeResourceGroupReuse`, `PublicIPAddressDNSSettingsDomainNameLabelScopeSubscriptionReuse`, `PublicIPAddressDNSSettingsDomainNameLabelScopeTenantReuse`
- New enum type `ScrubbingRuleEntryMatchOperator` with values `ScrubbingRuleEntryMatchOperatorEquals`, `ScrubbingRuleEntryMatchOperatorEqualsAny`
- New enum type `ScrubbingRuleEntryMatchVariable` with values `ScrubbingRuleEntryMatchVariableRequestArgNames`, `ScrubbingRuleEntryMatchVariableRequestCookieNames`, `ScrubbingRuleEntryMatchVariableRequestHeaderNames`, `ScrubbingRuleEntryMatchVariableRequestIPAddress`, `ScrubbingRuleEntryMatchVariableRequestJSONArgNames`, `ScrubbingRuleEntryMatchVariableRequestPostArgNames`
- New enum type `ScrubbingRuleEntryState` with values `ScrubbingRuleEntryStateDisabled`, `ScrubbingRuleEntryStateEnabled`
- New enum type `WebApplicationFirewallScrubbingState` with values `WebApplicationFirewallScrubbingStateDisabled`, `WebApplicationFirewallScrubbingStateEnabled`
- New function `*AzureFirewallsClient.BeginPacketCapture(context.Context, string, string, FirewallPacketCaptureParameters, *AzureFirewallsClientBeginPacketCaptureOptions) (*runtime.Poller[AzureFirewallsClientPacketCaptureResponse], error)`
- New function `*ClientFactory.NewVirtualApplianceConnectionsClient() *VirtualApplianceConnectionsClient`
- New function `NewVirtualApplianceConnectionsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*VirtualApplianceConnectionsClient, error)`
- New function `*VirtualApplianceConnectionsClient.BeginCreateOrUpdate(context.Context, string, string, string, VirtualApplianceConnection, *VirtualApplianceConnectionsClientBeginCreateOrUpdateOptions) (*runtime.Poller[VirtualApplianceConnectionsClientCreateOrUpdateResponse], error)`
- New function `*VirtualApplianceConnectionsClient.BeginDelete(context.Context, string, string, string, *VirtualApplianceConnectionsClientBeginDeleteOptions) (*runtime.Poller[VirtualApplianceConnectionsClientDeleteResponse], error)`
- New function `*VirtualApplianceConnectionsClient.Get(context.Context, string, string, string, *VirtualApplianceConnectionsClientGetOptions) (VirtualApplianceConnectionsClientGetResponse, error)`
- New function `*VirtualApplianceConnectionsClient.NewListPager(string, string, *VirtualApplianceConnectionsClientListOptions) *runtime.Pager[VirtualApplianceConnectionsClientListResponse]`
- New struct `AzureFirewallPacketCaptureFlags`
- New struct `AzureFirewallPacketCaptureRule`
- New struct `EffectiveRouteMapRouteList`
- New struct `FirewallPacketCaptureParameters`
- New struct `FirewallPacketCaptureParametersFormat`
- New struct `FirewallPolicyHTTPHeaderToInsert`
- New struct `GroupByUserSession`
- New struct `GroupByVariable`
- New struct `PolicySettingsLogScrubbing`
- New struct `PropagatedRouteTableNfv`
- New struct `RoutingConfigurationNfv`
- New struct `RoutingConfigurationNfvSubResource`
- New struct `VirtualApplianceAdditionalNicProperties`
- New struct `VirtualApplianceConnection`
- New struct `VirtualApplianceConnectionList`
- New struct `VirtualApplianceConnectionProperties`
- New struct `WebApplicationFirewallScrubbingRules`
- New field `HTTPHeadersToInsert` in struct `ApplicationRule`
- New field `EnableKerberos` in struct `BastionHostPropertiesFormat`
- New field `AuxiliarySKU` in struct `InterfacePropertiesFormat`
- New field `FileUploadEnforcement`, `LogScrubbing`, `RequestBodyEnforcement`, `RequestBodyInspectLimitInKB` in struct `PolicySettings`
- New field `PrivateEndpointLocation` in struct `PrivateEndpointConnectionProperties`
- New field `DomainNameLabelScope` in struct `PublicIPAddressDNSSettings`
- New field `InstanceName` in struct `VirtualApplianceNicProperties`
- New field `AdditionalNics`, `VirtualApplianceConnections` in struct `VirtualAppliancePropertiesFormat`
- New field `Value` in struct `VirtualHubBgpConnectionsClientListAdvertisedRoutesResponse`
- New field `Value` in struct `VirtualHubBgpConnectionsClientListLearnedRoutesResponse`
- New anonymous field `VirtualHubEffectiveRouteList` in struct `VirtualHubsClientGetEffectiveVirtualHubRoutesResponse`
- New anonymous field `EffectiveRouteMapRouteList` in struct `VirtualHubsClientGetInboundRoutesResponse`
- New anonymous field `EffectiveRouteMapRouteList` in struct `VirtualHubsClientGetOutboundRoutesResponse`
- New field `GroupByUserSession`, `RateLimitDuration`, `RateLimitThreshold` in struct `WebApplicationFirewallCustomRule`


## 2.2.1 (2023-04-14)
### Bug Fixes

- Fix serialization bug of empty value of `any` type.


## 2.2.0 (2023-03-24)
### Features Added

- New struct `ClientFactory` which is a client factory used to create any client in this module
- New value `ApplicationGatewayCustomErrorStatusCodeHTTPStatus400`, `ApplicationGatewayCustomErrorStatusCodeHTTPStatus404`, `ApplicationGatewayCustomErrorStatusCodeHTTPStatus405`, `ApplicationGatewayCustomErrorStatusCodeHTTPStatus408`, `ApplicationGatewayCustomErrorStatusCodeHTTPStatus499`, `ApplicationGatewayCustomErrorStatusCodeHTTPStatus500`, `ApplicationGatewayCustomErrorStatusCodeHTTPStatus503`, `ApplicationGatewayCustomErrorStatusCodeHTTPStatus504` added to enum type `ApplicationGatewayCustomErrorStatusCode`
- New enum type `WebApplicationFirewallState` with values `WebApplicationFirewallStateDisabled`, `WebApplicationFirewallStateEnabled`
- New field `AuthorizationStatus` in struct `ExpressRouteCircuitPropertiesFormat`
- New field `IPConfigurationID` in struct `VPNGatewaysClientBeginResetOptions`
- New field `FlowLogs` in struct `VirtualNetworkPropertiesFormat`
- New field `State` in struct `WebApplicationFirewallCustomRule`


## 2.1.0 (2022-12-23)
### Features Added

- New struct `DelegationProperties`
- New struct `PartnerManagedResourceProperties`
- New field `VirtualNetwork` in struct `BackendAddressPoolPropertiesFormat`
- New field `CustomBlockResponseBody` in struct `PolicySettings`
- New field `CustomBlockResponseStatusCode` in struct `PolicySettings`
- New field `Delegation` in struct `VirtualAppliancePropertiesFormat`
- New field `DeploymentType` in struct `VirtualAppliancePropertiesFormat`
- New field `PartnerManagedResource` in struct `VirtualAppliancePropertiesFormat`


## 2.0.1 (2022-10-14)
### Others Changes
- Update live test dependencies

## 2.0.0 (2022-09-29)
### Breaking Changes

- Const `DdosCustomPolicyProtocolSyn` has been removed
- Const `DdosCustomPolicyTriggerSensitivityOverrideHigh` has been removed
- Const `DdosSettingsProtectionCoverageBasic` has been removed
- Const `DdosCustomPolicyProtocolUDP` has been removed
- Const `DdosCustomPolicyProtocolTCP` has been removed
- Const `DdosCustomPolicyTriggerSensitivityOverrideLow` has been removed
- Const `DdosCustomPolicyTriggerSensitivityOverrideDefault` has been removed
- Const `DdosSettingsProtectionCoverageStandard` has been removed
- Const `DdosCustomPolicyTriggerSensitivityOverrideRelaxed` has been removed
- Type alias `DdosSettingsProtectionCoverage` has been removed
- Type alias `DdosCustomPolicyTriggerSensitivityOverride` has been removed
- Type alias `DdosCustomPolicyProtocol` has been removed
- Function `PossibleDdosCustomPolicyProtocolValues` has been removed
- Function `PossibleDdosSettingsProtectionCoverageValues` has been removed
- Function `PossibleDdosCustomPolicyTriggerSensitivityOverrideValues` has been removed
- Struct `ProtocolCustomSettingsFormat` has been removed
- Field `PublicIPAddresses` of struct `DdosCustomPolicyPropertiesFormat` has been removed
- Field `ProtocolCustomSettings` of struct `DdosCustomPolicyPropertiesFormat` has been removed
- Field `DdosCustomPolicy` of struct `DdosSettings` has been removed
- Field `ProtectedIP` of struct `DdosSettings` has been removed
- Field `ProtectionCoverage` of struct `DdosSettings` has been removed

### Features Added

- New const `ApplicationGatewayWafRuleStateTypesEnabled`
- New const `RouteMapMatchConditionNotEquals`
- New const `ActionTypeBlock`
- New const `RouteMapActionTypeUnknown`
- New const `GeoAFRI`
- New const `IsWorkloadProtectedFalse`
- New const `ApplicationGatewayRuleSetStatusOptionsDeprecated`
- New const `ApplicationGatewayWafRuleActionTypesAllow`
- New const `RouteMapActionTypeRemove`
- New const `ApplicationGatewayClientRevocationOptionsNone`
- New const `NextStepContinue`
- New const `SlotTypeProduction`
- New const `NetworkIntentPolicyBasedServiceAllowRulesOnly`
- New const `ApplicationGatewayTierTypesWAFV2`
- New const `ActionTypeLog`
- New const `CommissionedStateDeprovisioned`
- New const `RouteMapMatchConditionEquals`
- New const `GeoOCEANIA`
- New const `GeoGLOBAL`
- New const `WebApplicationFirewallTransformUppercase`
- New const `NextStepUnknown`
- New const `ApplicationGatewayTierTypesWAF`
- New const `ApplicationGatewayWafRuleActionTypesNone`
- New const `CustomIPPrefixTypeSingular`
- New const `GeoME`
- New const `GeoLATAM`
- New const `ApplicationGatewayWafRuleActionTypesBlock`
- New const `ApplicationGatewayRuleSetStatusOptionsGA`
- New const `RouteMapMatchConditionUnknown`
- New const `ApplicationGatewayWafRuleStateTypesDisabled`
- New const `ApplicationGatewayTierTypesStandardV2`
- New const `VnetLocalRouteOverrideCriteriaEqual`
- New const `ManagedRuleEnabledStateEnabled`
- New const `RouteMapMatchConditionContains`
- New const `DdosSettingsProtectionModeDisabled`
- New const `ActionTypeAnomalyScoring`
- New const `ActionTypeAllow`
- New const `SlotTypeStaging`
- New const `GeoAQ`
- New const `RouteMapMatchConditionNotContains`
- New const `ApplicationGatewayClientRevocationOptionsOCSP`
- New const `RouteMapActionTypeReplace`
- New const `GeoNAM`
- New const `CustomIPPrefixTypeChild`
- New const `GeoEURO`
- New const `ExpressRoutePortsBillingTypeMeteredData`
- New const `GeoAPAC`
- New const `CustomIPPrefixTypeParent`
- New const `VnetLocalRouteOverrideCriteriaContains`
- New const `DdosSettingsProtectionModeVirtualNetworkInherited`
- New const `ApplicationGatewayWafRuleActionTypesLog`
- New const `ApplicationGatewayWafRuleActionTypesAnomalyScoring`
- New const `ApplicationGatewayRuleSetStatusOptionsSupported`
- New const `ExpressRoutePortsBillingTypeUnlimitedData`
- New const `DdosSettingsProtectionModeEnabled`
- New const `IsWorkloadProtectedTrue`
- New const `ApplicationGatewayRuleSetStatusOptionsPreview`
- New const `RouteMapActionTypeDrop`
- New const `ApplicationGatewayTierTypesStandard`
- New const `NextStepTerminate`
- New const `RouteMapActionTypeAdd`
- New type alias `DdosSettingsProtectionMode`
- New type alias `ApplicationGatewayWafRuleActionTypes`
- New type alias `ApplicationGatewayClientRevocationOptions`
- New type alias `NextStep`
- New type alias `ActionType`
- New type alias `SlotType`
- New type alias `IsWorkloadProtected`
- New type alias `RouteMapMatchCondition`
- New type alias `ApplicationGatewayWafRuleStateTypes`
- New type alias `ApplicationGatewayTierTypes`
- New type alias `CustomIPPrefixType`
- New type alias `RouteMapActionType`
- New type alias `ExpressRoutePortsBillingType`
- New type alias `ApplicationGatewayRuleSetStatusOptions`
- New type alias `Geo`
- New type alias `VnetLocalRouteOverrideCriteria`
- New function `PossibleSlotTypeValues() []SlotType`
- New function `NewVipSwapClient(string, azcore.TokenCredential, *arm.ClientOptions) (*VipSwapClient, error)`
- New function `PossibleNextStepValues() []NextStep`
- New function `*RouteMapsClient.BeginDelete(context.Context, string, string, string, *RouteMapsClientBeginDeleteOptions) (*runtime.Poller[RouteMapsClientDeleteResponse], error)`
- New function `PossibleRouteMapActionTypeValues() []RouteMapActionType`
- New function `*RouteMapsClient.Get(context.Context, string, string, string, *RouteMapsClientGetOptions) (RouteMapsClientGetResponse, error)`
- New function `*VirtualHubsClient.BeginGetOutboundRoutes(context.Context, string, string, GetOutboundRoutesParameters, *VirtualHubsClientBeginGetOutboundRoutesOptions) (*runtime.Poller[VirtualHubsClientGetOutboundRoutesResponse], error)`
- New function `PossibleGeoValues() []Geo`
- New function `PossibleApplicationGatewayClientRevocationOptionsValues() []ApplicationGatewayClientRevocationOptions`
- New function `*ApplicationGatewayWafDynamicManifestsClient.NewGetPager(string, *ApplicationGatewayWafDynamicManifestsClientGetOptions) *runtime.Pager[ApplicationGatewayWafDynamicManifestsClientGetResponse]`
- New function `*ApplicationGatewayWafDynamicManifestsDefaultClient.Get(context.Context, string, *ApplicationGatewayWafDynamicManifestsDefaultClientGetOptions) (ApplicationGatewayWafDynamicManifestsDefaultClientGetResponse, error)`
- New function `PossibleActionTypeValues() []ActionType`
- New function `*RouteMapsClient.NewListPager(string, string, *RouteMapsClientListOptions) *runtime.Pager[RouteMapsClientListResponse]`
- New function `PossibleApplicationGatewayTierTypesValues() []ApplicationGatewayTierTypes`
- New function `NewApplicationGatewayWafDynamicManifestsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*ApplicationGatewayWafDynamicManifestsClient, error)`
- New function `PossibleApplicationGatewayRuleSetStatusOptionsValues() []ApplicationGatewayRuleSetStatusOptions`
- New function `PossibleCustomIPPrefixTypeValues() []CustomIPPrefixType`
- New function `NewApplicationGatewayWafDynamicManifestsDefaultClient(string, azcore.TokenCredential, *arm.ClientOptions) (*ApplicationGatewayWafDynamicManifestsDefaultClient, error)`
- New function `PossibleVnetLocalRouteOverrideCriteriaValues() []VnetLocalRouteOverrideCriteria`
- New function `*VirtualHubsClient.BeginGetInboundRoutes(context.Context, string, string, GetInboundRoutesParameters, *VirtualHubsClientBeginGetInboundRoutesOptions) (*runtime.Poller[VirtualHubsClientGetInboundRoutesResponse], error)`
- New function `*VipSwapClient.Get(context.Context, string, string, *VipSwapClientGetOptions) (VipSwapClientGetResponse, error)`
- New function `*PublicIPAddressesClient.BeginDdosProtectionStatus(context.Context, string, string, *PublicIPAddressesClientBeginDdosProtectionStatusOptions) (*runtime.Poller[PublicIPAddressesClientDdosProtectionStatusResponse], error)`
- New function `PossibleExpressRoutePortsBillingTypeValues() []ExpressRoutePortsBillingType`
- New function `*VipSwapClient.List(context.Context, string, string, *VipSwapClientListOptions) (VipSwapClientListResponse, error)`
- New function `*VirtualNetworksClient.BeginListDdosProtectionStatus(context.Context, string, string, *VirtualNetworksClientBeginListDdosProtectionStatusOptions) (*runtime.Poller[*runtime.Pager[VirtualNetworksClientListDdosProtectionStatusResponse]], error)`
- New function `PossibleIsWorkloadProtectedValues() []IsWorkloadProtected`
- New function `PossibleDdosSettingsProtectionModeValues() []DdosSettingsProtectionMode`
- New function `PossibleApplicationGatewayWafRuleStateTypesValues() []ApplicationGatewayWafRuleStateTypes`
- New function `NewRouteMapsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*RouteMapsClient, error)`
- New function `PossibleRouteMapMatchConditionValues() []RouteMapMatchCondition`
- New function `*VipSwapClient.BeginCreate(context.Context, string, string, SwapResource, *VipSwapClientBeginCreateOptions) (*runtime.Poller[VipSwapClientCreateResponse], error)`
- New function `PossibleApplicationGatewayWafRuleActionTypesValues() []ApplicationGatewayWafRuleActionTypes`
- New function `*RouteMapsClient.BeginCreateOrUpdate(context.Context, string, string, string, RouteMap, *RouteMapsClientBeginCreateOrUpdateOptions) (*runtime.Poller[RouteMapsClientCreateOrUpdateResponse], error)`
- New struct `Action`
- New struct `ApplicationGatewayFirewallManifestRuleSet`
- New struct `ApplicationGatewayWafDynamicManifestPropertiesResult`
- New struct `ApplicationGatewayWafDynamicManifestResult`
- New struct `ApplicationGatewayWafDynamicManifestResultList`
- New struct `ApplicationGatewayWafDynamicManifestsClient`
- New struct `ApplicationGatewayWafDynamicManifestsClientGetOptions`
- New struct `ApplicationGatewayWafDynamicManifestsClientGetResponse`
- New struct `ApplicationGatewayWafDynamicManifestsDefaultClient`
- New struct `ApplicationGatewayWafDynamicManifestsDefaultClientGetOptions`
- New struct `ApplicationGatewayWafDynamicManifestsDefaultClientGetResponse`
- New struct `Criterion`
- New struct `DefaultRuleSetPropertyFormat`
- New struct `EffectiveRouteMapRoute`
- New struct `GetInboundRoutesParameters`
- New struct `GetOutboundRoutesParameters`
- New struct `ListRouteMapsResult`
- New struct `Parameter`
- New struct `PublicIPAddressesClientBeginDdosProtectionStatusOptions`
- New struct `PublicIPAddressesClientDdosProtectionStatusResponse`
- New struct `PublicIPDdosProtectionStatusResult`
- New struct `RouteMap`
- New struct `RouteMapProperties`
- New struct `RouteMapRule`
- New struct `RouteMapsClient`
- New struct `RouteMapsClientBeginCreateOrUpdateOptions`
- New struct `RouteMapsClientBeginDeleteOptions`
- New struct `RouteMapsClientCreateOrUpdateResponse`
- New struct `RouteMapsClientDeleteResponse`
- New struct `RouteMapsClientGetOptions`
- New struct `RouteMapsClientGetResponse`
- New struct `RouteMapsClientListOptions`
- New struct `RouteMapsClientListResponse`
- New struct `StaticRoutesConfig`
- New struct `SwapResource`
- New struct `SwapResourceListResult`
- New struct `SwapResourceProperties`
- New struct `VipSwapClient`
- New struct `VipSwapClientBeginCreateOptions`
- New struct `VipSwapClientCreateResponse`
- New struct `VipSwapClientGetOptions`
- New struct `VipSwapClientGetResponse`
- New struct `VipSwapClientListOptions`
- New struct `VipSwapClientListResponse`
- New struct `VirtualHubsClientBeginGetInboundRoutesOptions`
- New struct `VirtualHubsClientBeginGetOutboundRoutesOptions`
- New struct `VirtualHubsClientGetInboundRoutesResponse`
- New struct `VirtualHubsClientGetOutboundRoutesResponse`
- New struct `VirtualNetworkDdosProtectionStatusResult`
- New struct `VirtualNetworkGatewayPolicyGroup`
- New struct `VirtualNetworkGatewayPolicyGroupMember`
- New struct `VirtualNetworkGatewayPolicyGroupProperties`
- New struct `VirtualNetworksClientBeginListDdosProtectionStatusOptions`
- New struct `VirtualNetworksClientListDdosProtectionStatusResponse`
- New struct `VngClientConnectionConfiguration`
- New struct `VngClientConnectionConfigurationProperties`
- New field `RouteMaps` in struct `VirtualHubProperties`
- New field `Tiers` in struct `ApplicationGatewayFirewallRuleSetPropertiesFormat`
- New field `EnablePrivateLinkFastPath` in struct `VirtualNetworkGatewayConnectionListEntityPropertiesFormat`
- New field `ColoLocation` in struct `ExpressRouteLinkPropertiesFormat`
- New field `EnablePrivateLinkFastPath` in struct `VirtualNetworkGatewayConnectionPropertiesFormat`
- New field `DisableTCPStateTracking` in struct `InterfacePropertiesFormat`
- New field `Top` in struct `ManagementClientListNetworkManagerEffectiveConnectivityConfigurationsOptions`
- New field `Action` in struct `ManagedRuleOverride`
- New field `VngClientConnectionConfigurations` in struct `VPNClientConfiguration`
- New field `StaticRoutesConfig` in struct `VnetRoute`
- New field `AllowVirtualWanTraffic` in struct `VirtualNetworkGatewayPropertiesFormat`
- New field `VirtualNetworkGatewayPolicyGroups` in struct `VirtualNetworkGatewayPropertiesFormat`
- New field `AllowRemoteVnetTraffic` in struct `VirtualNetworkGatewayPropertiesFormat`
- New field `RuleIDString` in struct `ApplicationGatewayFirewallRule`
- New field `State` in struct `ApplicationGatewayFirewallRule`
- New field `Action` in struct `ApplicationGatewayFirewallRule`
- New field `Top` in struct `ManagerDeploymentStatusClientListOptions`
- New field `InboundRouteMap` in struct `RoutingConfiguration`
- New field `OutboundRouteMap` in struct `RoutingConfiguration`
- New field `VerifyClientRevocation` in struct `ApplicationGatewayClientAuthConfiguration`
- New field `Top` in struct `ManagementClientListActiveSecurityAdminRulesOptions`
- New field `ProbeThreshold` in struct `ProbePropertiesFormat`
- New field `AllowNonVirtualWanTraffic` in struct `ExpressRouteGatewayProperties`
- New field `Top` in struct `ManagementClientListActiveConnectivityConfigurationsOptions`
- New field `PublicIPAddresses` in struct `DdosProtectionPlanPropertiesFormat`
- New field `ProtectionMode` in struct `DdosSettings`
- New field `DdosProtectionPlan` in struct `DdosSettings`
- New field `ExpressRouteAdvertise` in struct `CustomIPPrefixPropertiesFormat`
- New field `Geo` in struct `CustomIPPrefixPropertiesFormat`
- New field `PrefixType` in struct `CustomIPPrefixPropertiesFormat`
- New field `Asn` in struct `CustomIPPrefixPropertiesFormat`
- New field `Top` in struct `ManagementClientListNetworkManagerEffectiveSecurityAdminRulesOptions`
- New field `EnablePrivateLinkFastPath` in struct `ExpressRouteConnectionProperties`
- New field `BillingType` in struct `ExpressRoutePortPropertiesFormat`


## 1.1.0 (2022-08-05)
### Features Added

- New const `SecurityConfigurationRuleDirectionInbound`
- New const `IsGlobalFalse`
- New const `EndpointTypeAzureVMSS`
- New const `ScopeConnectionStateConflict`
- New const `SecurityConfigurationRuleDirectionOutbound`
- New const `GroupConnectivityDirectlyConnected`
- New const `ScopeConnectionStateRejected`
- New const `ConfigurationTypeConnectivity`
- New const `AutoLearnPrivateRangesModeEnabled`
- New const `UseHubGatewayFalse`
- New const `NetworkIntentPolicyBasedServiceNone`
- New const `DeleteExistingPeeringFalse`
- New const `EffectiveAdminRuleKindDefault`
- New const `DeploymentStatusFailed`
- New const `AddressPrefixTypeIPPrefix`
- New const `AddressPrefixTypeServiceTag`
- New const `UseHubGatewayTrue`
- New const `WebApplicationFirewallOperatorAny`
- New const `SecurityConfigurationRuleAccessAlwaysAllow`
- New const `CreatedByTypeUser`
- New const `EndpointTypeAzureArcVM`
- New const `DeploymentStatusNotStarted`
- New const `SecurityConfigurationRuleProtocolTCP`
- New const `SecurityConfigurationRuleAccessDeny`
- New const `SecurityConfigurationRuleProtocolEsp`
- New const `IsGlobalTrue`
- New const `DeploymentStatusDeployed`
- New const `NetworkIntentPolicyBasedServiceAll`
- New const `SecurityConfigurationRuleProtocolUDP`
- New const `CreatedByTypeKey`
- New const `PacketCaptureTargetTypeAzureVMSS`
- New const `ApplicationGatewaySSLPolicyTypeCustomV2`
- New const `DeleteExistingPeeringTrue`
- New const `ScopeConnectionStateConnected`
- New const `ApplicationGatewaySSLPolicyNameAppGwSSLPolicy20220101S`
- New const `ConnectivityTopologyMesh`
- New const `CreatedByTypeManagedIdentity`
- New const `AdminRuleKindCustom`
- New const `ApplicationGatewaySSLProtocolTLSv13`
- New const `ConnectivityTopologyHubAndSpoke`
- New const `ScopeConnectionStateRevoked`
- New const `ConfigurationTypeSecurityAdmin`
- New const `SecurityConfigurationRuleProtocolAh`
- New const `CommissionedStateCommissionedNoInternetAdvertise`
- New const `ScopeConnectionStatePending`
- New const `SecurityConfigurationRuleAccessAllow`
- New const `SecurityConfigurationRuleProtocolIcmp`
- New const `AutoLearnPrivateRangesModeDisabled`
- New const `SecurityConfigurationRuleProtocolAny`
- New const `ApplicationGatewaySSLPolicyNameAppGwSSLPolicy20220101`
- New const `CreatedByTypeApplication`
- New const `GroupConnectivityNone`
- New const `EffectiveAdminRuleKindCustom`
- New const `AdminRuleKindDefault`
- New const `DeploymentStatusDeploying`
- New const `PacketCaptureTargetTypeAzureVM`
- New function `*ManagementClient.ListActiveConnectivityConfigurations(context.Context, string, string, ActiveConfigurationParameter, *ManagementClientListActiveConnectivityConfigurationsOptions) (ManagementClientListActiveConnectivityConfigurationsResponse, error)`
- New function `*ManagersClient.NewListBySubscriptionPager(*ManagersClientListBySubscriptionOptions) *runtime.Pager[ManagersClientListBySubscriptionResponse]`
- New function `NewStaticMembersClient(string, azcore.TokenCredential, *arm.ClientOptions) (*StaticMembersClient, error)`
- New function `NewAdminRulesClient(string, azcore.TokenCredential, *arm.ClientOptions) (*AdminRulesClient, error)`
- New function `*EffectiveDefaultSecurityAdminRule.GetEffectiveBaseSecurityAdminRule() *EffectiveBaseSecurityAdminRule`
- New function `PossibleAddressPrefixTypeValues() []AddressPrefixType`
- New function `PossibleUseHubGatewayValues() []UseHubGateway`
- New function `*ScopeConnectionsClient.Delete(context.Context, string, string, string, *ScopeConnectionsClientDeleteOptions) (ScopeConnectionsClientDeleteResponse, error)`
- New function `PossibleIsGlobalValues() []IsGlobal`
- New function `*ManagementClient.ListActiveSecurityAdminRules(context.Context, string, string, ActiveConfigurationParameter, *ManagementClientListActiveSecurityAdminRulesOptions) (ManagementClientListActiveSecurityAdminRulesResponse, error)`
- New function `*ManagersClient.NewListPager(string, *ManagersClientListOptions) *runtime.Pager[ManagersClientListResponse]`
- New function `NewConnectivityConfigurationsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*ConnectivityConfigurationsClient, error)`
- New function `*GroupsClient.Get(context.Context, string, string, string, *GroupsClientGetOptions) (GroupsClientGetResponse, error)`
- New function `PossibleAdminRuleKindValues() []AdminRuleKind`
- New function `*ScopeConnectionsClient.Get(context.Context, string, string, string, *ScopeConnectionsClientGetOptions) (ScopeConnectionsClientGetResponse, error)`
- New function `*AdminRuleCollectionsClient.CreateOrUpdate(context.Context, string, string, string, string, AdminRuleCollection, *AdminRuleCollectionsClientCreateOrUpdateOptions) (AdminRuleCollectionsClientCreateOrUpdateResponse, error)`
- New function `PossibleScopeConnectionStateValues() []ScopeConnectionState`
- New function `*ConnectivityConfigurationsClient.NewListPager(string, string, *ConnectivityConfigurationsClientListOptions) *runtime.Pager[ConnectivityConfigurationsClientListResponse]`
- New function `*BaseAdminRule.GetBaseAdminRule() *BaseAdminRule`
- New function `PossibleSecurityConfigurationRuleProtocolValues() []SecurityConfigurationRuleProtocol`
- New function `*AdminRulesClient.CreateOrUpdate(context.Context, string, string, string, string, string, BaseAdminRuleClassification, *AdminRulesClientCreateOrUpdateOptions) (AdminRulesClientCreateOrUpdateResponse, error)`
- New function `PossibleNetworkIntentPolicyBasedServiceValues() []NetworkIntentPolicyBasedService`
- New function `*ManagementGroupNetworkManagerConnectionsClient.Delete(context.Context, string, string, *ManagementGroupNetworkManagerConnectionsClientDeleteOptions) (ManagementGroupNetworkManagerConnectionsClientDeleteResponse, error)`
- New function `PossibleSecurityConfigurationRuleAccessValues() []SecurityConfigurationRuleAccess`
- New function `*ManagersClient.BeginDelete(context.Context, string, string, *ManagersClientBeginDeleteOptions) (*runtime.Poller[ManagersClientDeleteResponse], error)`
- New function `*ManagementClient.ExpressRouteProviderPort(context.Context, string, *ManagementClientExpressRouteProviderPortOptions) (ManagementClientExpressRouteProviderPortResponse, error)`
- New function `*ActiveBaseSecurityAdminRule.GetActiveBaseSecurityAdminRule() *ActiveBaseSecurityAdminRule`
- New function `*ConnectivityConfigurationsClient.BeginDelete(context.Context, string, string, string, *ConnectivityConfigurationsClientBeginDeleteOptions) (*runtime.Poller[ConnectivityConfigurationsClientDeleteResponse], error)`
- New function `*AdminRuleCollectionsClient.BeginDelete(context.Context, string, string, string, string, *AdminRuleCollectionsClientBeginDeleteOptions) (*runtime.Poller[AdminRuleCollectionsClientDeleteResponse], error)`
- New function `*ConnectivityConfigurationsClient.CreateOrUpdate(context.Context, string, string, string, ConnectivityConfiguration, *ConnectivityConfigurationsClientCreateOrUpdateOptions) (ConnectivityConfigurationsClientCreateOrUpdateResponse, error)`
- New function `*SecurityAdminConfigurationsClient.Get(context.Context, string, string, string, *SecurityAdminConfigurationsClientGetOptions) (SecurityAdminConfigurationsClientGetResponse, error)`
- New function `*StaticMembersClient.Delete(context.Context, string, string, string, string, *StaticMembersClientDeleteOptions) (StaticMembersClientDeleteResponse, error)`
- New function `*ManagerDeploymentStatusClient.List(context.Context, string, string, ManagerDeploymentStatusParameter, *ManagerDeploymentStatusClientListOptions) (ManagerDeploymentStatusClientListResponse, error)`
- New function `*SubscriptionNetworkManagerConnectionsClient.Delete(context.Context, string, *SubscriptionNetworkManagerConnectionsClientDeleteOptions) (SubscriptionNetworkManagerConnectionsClientDeleteResponse, error)`
- New function `PossibleEffectiveAdminRuleKindValues() []EffectiveAdminRuleKind`
- New function `*AdminRulesClient.NewListPager(string, string, string, string, *AdminRulesClientListOptions) *runtime.Pager[AdminRulesClientListResponse]`
- New function `*GroupsClient.NewListPager(string, string, *GroupsClientListOptions) *runtime.Pager[GroupsClientListResponse]`
- New function `*GroupsClient.BeginDelete(context.Context, string, string, string, *GroupsClientBeginDeleteOptions) (*runtime.Poller[GroupsClientDeleteResponse], error)`
- New function `*StaticMembersClient.NewListPager(string, string, string, *StaticMembersClientListOptions) *runtime.Pager[StaticMembersClientListResponse]`
- New function `NewGroupsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*GroupsClient, error)`
- New function `PossibleCreatedByTypeValues() []CreatedByType`
- New function `PossibleAutoLearnPrivateRangesModeValues() []AutoLearnPrivateRangesMode`
- New function `*ManagementGroupNetworkManagerConnectionsClient.CreateOrUpdate(context.Context, string, string, ManagerConnection, *ManagementGroupNetworkManagerConnectionsClientCreateOrUpdateOptions) (ManagementGroupNetworkManagerConnectionsClientCreateOrUpdateResponse, error)`
- New function `*GroupsClient.CreateOrUpdate(context.Context, string, string, string, Group, *GroupsClientCreateOrUpdateOptions) (GroupsClientCreateOrUpdateResponse, error)`
- New function `*ActiveSecurityAdminRule.GetActiveBaseSecurityAdminRule() *ActiveBaseSecurityAdminRule`
- New function `*AdminRuleCollectionsClient.Get(context.Context, string, string, string, string, *AdminRuleCollectionsClientGetOptions) (AdminRuleCollectionsClientGetResponse, error)`
- New function `*ManagersClient.CreateOrUpdate(context.Context, string, string, Manager, *ManagersClientCreateOrUpdateOptions) (ManagersClientCreateOrUpdateResponse, error)`
- New function `*SubscriptionNetworkManagerConnectionsClient.NewListPager(*SubscriptionNetworkManagerConnectionsClientListOptions) *runtime.Pager[SubscriptionNetworkManagerConnectionsClientListResponse]`
- New function `*AdminRule.GetBaseAdminRule() *BaseAdminRule`
- New function `*AdminRulesClient.Get(context.Context, string, string, string, string, string, *AdminRulesClientGetOptions) (AdminRulesClientGetResponse, error)`
- New function `PossiblePacketCaptureTargetTypeValues() []PacketCaptureTargetType`
- New function `*ManagementClient.ListNetworkManagerEffectiveSecurityAdminRules(context.Context, string, string, QueryRequestOptions, *ManagementClientListNetworkManagerEffectiveSecurityAdminRulesOptions) (ManagementClientListNetworkManagerEffectiveSecurityAdminRulesResponse, error)`
- New function `*ManagementGroupNetworkManagerConnectionsClient.Get(context.Context, string, string, *ManagementGroupNetworkManagerConnectionsClientGetOptions) (ManagementGroupNetworkManagerConnectionsClientGetResponse, error)`
- New function `NewExpressRouteProviderPortsLocationClient(string, azcore.TokenCredential, *arm.ClientOptions) (*ExpressRouteProviderPortsLocationClient, error)`
- New function `*DefaultAdminRule.GetBaseAdminRule() *BaseAdminRule`
- New function `*ConnectivityConfigurationsClient.Get(context.Context, string, string, string, *ConnectivityConfigurationsClientGetOptions) (ConnectivityConfigurationsClientGetResponse, error)`
- New function `NewManagersClient(string, azcore.TokenCredential, *arm.ClientOptions) (*ManagersClient, error)`
- New function `*SubscriptionNetworkManagerConnectionsClient.Get(context.Context, string, *SubscriptionNetworkManagerConnectionsClientGetOptions) (SubscriptionNetworkManagerConnectionsClientGetResponse, error)`
- New function `*EffectiveSecurityAdminRule.GetEffectiveBaseSecurityAdminRule() *EffectiveBaseSecurityAdminRule`
- New function `*EffectiveBaseSecurityAdminRule.GetEffectiveBaseSecurityAdminRule() *EffectiveBaseSecurityAdminRule`
- New function `NewScopeConnectionsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*ScopeConnectionsClient, error)`
- New function `NewAdminRuleCollectionsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*AdminRuleCollectionsClient, error)`
- New function `*ManagementClient.ListNetworkManagerEffectiveConnectivityConfigurations(context.Context, string, string, QueryRequestOptions, *ManagementClientListNetworkManagerEffectiveConnectivityConfigurationsOptions) (ManagementClientListNetworkManagerEffectiveConnectivityConfigurationsResponse, error)`
- New function `PossibleGroupConnectivityValues() []GroupConnectivity`
- New function `NewSubscriptionNetworkManagerConnectionsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*SubscriptionNetworkManagerConnectionsClient, error)`
- New function `*AzureFirewallsClient.BeginListLearnedPrefixes(context.Context, string, string, *AzureFirewallsClientBeginListLearnedPrefixesOptions) (*runtime.Poller[AzureFirewallsClientListLearnedPrefixesResponse], error)`
- New function `*ManagersClient.Patch(context.Context, string, string, PatchObject, *ManagersClientPatchOptions) (ManagersClientPatchResponse, error)`
- New function `*ManagersClient.Get(context.Context, string, string, *ManagersClientGetOptions) (ManagersClientGetResponse, error)`
- New function `*StaticMembersClient.CreateOrUpdate(context.Context, string, string, string, string, StaticMember, *StaticMembersClientCreateOrUpdateOptions) (StaticMembersClientCreateOrUpdateResponse, error)`
- New function `*AdminRuleCollectionsClient.NewListPager(string, string, string, *AdminRuleCollectionsClientListOptions) *runtime.Pager[AdminRuleCollectionsClientListResponse]`
- New function `*ScopeConnectionsClient.NewListPager(string, string, *ScopeConnectionsClientListOptions) *runtime.Pager[ScopeConnectionsClientListResponse]`
- New function `*ActiveDefaultSecurityAdminRule.GetActiveBaseSecurityAdminRule() *ActiveBaseSecurityAdminRule`
- New function `*ExpressRouteProviderPortsLocationClient.List(context.Context, *ExpressRouteProviderPortsLocationClientListOptions) (ExpressRouteProviderPortsLocationClientListResponse, error)`
- New function `*ManagerCommitsClient.BeginPost(context.Context, string, string, ManagerCommit, *ManagerCommitsClientBeginPostOptions) (*runtime.Poller[ManagerCommitsClientPostResponse], error)`
- New function `NewManagerCommitsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*ManagerCommitsClient, error)`
- New function `PossibleConfigurationTypeValues() []ConfigurationType`
- New function `NewManagerDeploymentStatusClient(string, azcore.TokenCredential, *arm.ClientOptions) (*ManagerDeploymentStatusClient, error)`
- New function `*ScopeConnectionsClient.CreateOrUpdate(context.Context, string, string, string, ScopeConnection, *ScopeConnectionsClientCreateOrUpdateOptions) (ScopeConnectionsClientCreateOrUpdateResponse, error)`
- New function `*SecurityAdminConfigurationsClient.CreateOrUpdate(context.Context, string, string, string, SecurityAdminConfiguration, *SecurityAdminConfigurationsClientCreateOrUpdateOptions) (SecurityAdminConfigurationsClientCreateOrUpdateResponse, error)`
- New function `NewManagementGroupNetworkManagerConnectionsClient(azcore.TokenCredential, *arm.ClientOptions) (*ManagementGroupNetworkManagerConnectionsClient, error)`
- New function `PossibleDeleteExistingPeeringValues() []DeleteExistingPeering`
- New function `PossibleDeploymentStatusValues() []DeploymentStatus`
- New function `*ManagementGroupNetworkManagerConnectionsClient.NewListPager(string, *ManagementGroupNetworkManagerConnectionsClientListOptions) *runtime.Pager[ManagementGroupNetworkManagerConnectionsClientListResponse]`
- New function `*SecurityAdminConfigurationsClient.NewListPager(string, string, *SecurityAdminConfigurationsClientListOptions) *runtime.Pager[SecurityAdminConfigurationsClientListResponse]`
- New function `PossibleConnectivityTopologyValues() []ConnectivityTopology`
- New function `*StaticMembersClient.Get(context.Context, string, string, string, string, *StaticMembersClientGetOptions) (StaticMembersClientGetResponse, error)`
- New function `PossibleSecurityConfigurationRuleDirectionValues() []SecurityConfigurationRuleDirection`
- New function `*SecurityAdminConfigurationsClient.BeginDelete(context.Context, string, string, string, *SecurityAdminConfigurationsClientBeginDeleteOptions) (*runtime.Poller[SecurityAdminConfigurationsClientDeleteResponse], error)`
- New function `NewSecurityAdminConfigurationsClient(string, azcore.TokenCredential, *arm.ClientOptions) (*SecurityAdminConfigurationsClient, error)`
- New function `*AdminRulesClient.BeginDelete(context.Context, string, string, string, string, string, *AdminRulesClientBeginDeleteOptions) (*runtime.Poller[AdminRulesClientDeleteResponse], error)`
- New function `*SubscriptionNetworkManagerConnectionsClient.CreateOrUpdate(context.Context, string, ManagerConnection, *SubscriptionNetworkManagerConnectionsClientCreateOrUpdateOptions) (SubscriptionNetworkManagerConnectionsClientCreateOrUpdateResponse, error)`
- New struct `ActiveBaseSecurityAdminRule`
- New struct `ActiveConfigurationParameter`
- New struct `ActiveConnectivityConfiguration`
- New struct `ActiveConnectivityConfigurationsListResult`
- New struct `ActiveDefaultSecurityAdminRule`
- New struct `ActiveSecurityAdminRule`
- New struct `ActiveSecurityAdminRulesListResult`
- New struct `AddressPrefixItem`
- New struct `AdminPropertiesFormat`
- New struct `AdminRule`
- New struct `AdminRuleCollection`
- New struct `AdminRuleCollectionListResult`
- New struct `AdminRuleCollectionPropertiesFormat`
- New struct `AdminRuleCollectionsClient`
- New struct `AdminRuleCollectionsClientBeginDeleteOptions`
- New struct `AdminRuleCollectionsClientCreateOrUpdateOptions`
- New struct `AdminRuleCollectionsClientCreateOrUpdateResponse`
- New struct `AdminRuleCollectionsClientDeleteResponse`
- New struct `AdminRuleCollectionsClientGetOptions`
- New struct `AdminRuleCollectionsClientGetResponse`
- New struct `AdminRuleCollectionsClientListOptions`
- New struct `AdminRuleCollectionsClientListResponse`
- New struct `AdminRuleListResult`
- New struct `AdminRulesClient`
- New struct `AdminRulesClientBeginDeleteOptions`
- New struct `AdminRulesClientCreateOrUpdateOptions`
- New struct `AdminRulesClientCreateOrUpdateResponse`
- New struct `AdminRulesClientDeleteResponse`
- New struct `AdminRulesClientGetOptions`
- New struct `AdminRulesClientGetResponse`
- New struct `AdminRulesClientListOptions`
- New struct `AdminRulesClientListResponse`
- New struct `AzureFirewallsClientBeginListLearnedPrefixesOptions`
- New struct `AzureFirewallsClientListLearnedPrefixesResponse`
- New struct `BaseAdminRule`
- New struct `ChildResource`
- New struct `ConfigurationGroup`
- New struct `ConnectivityConfiguration`
- New struct `ConnectivityConfigurationListResult`
- New struct `ConnectivityConfigurationProperties`
- New struct `ConnectivityConfigurationsClient`
- New struct `ConnectivityConfigurationsClientBeginDeleteOptions`
- New struct `ConnectivityConfigurationsClientCreateOrUpdateOptions`
- New struct `ConnectivityConfigurationsClientCreateOrUpdateResponse`
- New struct `ConnectivityConfigurationsClientDeleteResponse`
- New struct `ConnectivityConfigurationsClientGetOptions`
- New struct `ConnectivityConfigurationsClientGetResponse`
- New struct `ConnectivityConfigurationsClientListOptions`
- New struct `ConnectivityConfigurationsClientListResponse`
- New struct `ConnectivityGroupItem`
- New struct `CrossTenantScopes`
- New struct `DefaultAdminPropertiesFormat`
- New struct `DefaultAdminRule`
- New struct `EffectiveBaseSecurityAdminRule`
- New struct `EffectiveConnectivityConfiguration`
- New struct `EffectiveDefaultSecurityAdminRule`
- New struct `EffectiveSecurityAdminRule`
- New struct `ExpressRouteProviderPort`
- New struct `ExpressRouteProviderPortListResult`
- New struct `ExpressRouteProviderPortProperties`
- New struct `ExpressRouteProviderPortsLocationClient`
- New struct `ExpressRouteProviderPortsLocationClientListOptions`
- New struct `ExpressRouteProviderPortsLocationClientListResponse`
- New struct `Group`
- New struct `GroupListResult`
- New struct `GroupProperties`
- New struct `GroupsClient`
- New struct `GroupsClientBeginDeleteOptions`
- New struct `GroupsClientCreateOrUpdateOptions`
- New struct `GroupsClientCreateOrUpdateResponse`
- New struct `GroupsClientDeleteResponse`
- New struct `GroupsClientGetOptions`
- New struct `GroupsClientGetResponse`
- New struct `GroupsClientListOptions`
- New struct `GroupsClientListResponse`
- New struct `Hub`
- New struct `IPPrefixesList`
- New struct `ManagementClientExpressRouteProviderPortOptions`
- New struct `ManagementClientExpressRouteProviderPortResponse`
- New struct `ManagementClientListActiveConnectivityConfigurationsOptions`
- New struct `ManagementClientListActiveConnectivityConfigurationsResponse`
- New struct `ManagementClientListActiveSecurityAdminRulesOptions`
- New struct `ManagementClientListActiveSecurityAdminRulesResponse`
- New struct `ManagementClientListNetworkManagerEffectiveConnectivityConfigurationsOptions`
- New struct `ManagementClientListNetworkManagerEffectiveConnectivityConfigurationsResponse`
- New struct `ManagementClientListNetworkManagerEffectiveSecurityAdminRulesOptions`
- New struct `ManagementClientListNetworkManagerEffectiveSecurityAdminRulesResponse`
- New struct `ManagementGroupNetworkManagerConnectionsClient`
- New struct `ManagementGroupNetworkManagerConnectionsClientCreateOrUpdateOptions`
- New struct `ManagementGroupNetworkManagerConnectionsClientCreateOrUpdateResponse`
- New struct `ManagementGroupNetworkManagerConnectionsClientDeleteOptions`
- New struct `ManagementGroupNetworkManagerConnectionsClientDeleteResponse`
- New struct `ManagementGroupNetworkManagerConnectionsClientGetOptions`
- New struct `ManagementGroupNetworkManagerConnectionsClientGetResponse`
- New struct `ManagementGroupNetworkManagerConnectionsClientListOptions`
- New struct `ManagementGroupNetworkManagerConnectionsClientListResponse`
- New struct `Manager`
- New struct `ManagerCommit`
- New struct `ManagerCommitsClient`
- New struct `ManagerCommitsClientBeginPostOptions`
- New struct `ManagerCommitsClientPostResponse`
- New struct `ManagerConnection`
- New struct `ManagerConnectionListResult`
- New struct `ManagerConnectionProperties`
- New struct `ManagerDeploymentStatus`
- New struct `ManagerDeploymentStatusClient`
- New struct `ManagerDeploymentStatusClientListOptions`
- New struct `ManagerDeploymentStatusClientListResponse`
- New struct `ManagerDeploymentStatusListResult`
- New struct `ManagerDeploymentStatusParameter`
- New struct `ManagerEffectiveConnectivityConfigurationListResult`
- New struct `ManagerEffectiveSecurityAdminRulesListResult`
- New struct `ManagerListResult`
- New struct `ManagerProperties`
- New struct `ManagerPropertiesNetworkManagerScopes`
- New struct `ManagerSecurityGroupItem`
- New struct `ManagersClient`
- New struct `ManagersClientBeginDeleteOptions`
- New struct `ManagersClientCreateOrUpdateOptions`
- New struct `ManagersClientCreateOrUpdateResponse`
- New struct `ManagersClientDeleteResponse`
- New struct `ManagersClientGetOptions`
- New struct `ManagersClientGetResponse`
- New struct `ManagersClientListBySubscriptionOptions`
- New struct `ManagersClientListBySubscriptionResponse`
- New struct `ManagersClientListOptions`
- New struct `ManagersClientListResponse`
- New struct `ManagersClientPatchOptions`
- New struct `ManagersClientPatchResponse`
- New struct `PacketCaptureMachineScope`
- New struct `PatchObject`
- New struct `QueryRequestOptions`
- New struct `ScopeConnection`
- New struct `ScopeConnectionListResult`
- New struct `ScopeConnectionProperties`
- New struct `ScopeConnectionsClient`
- New struct `ScopeConnectionsClientCreateOrUpdateOptions`
- New struct `ScopeConnectionsClientCreateOrUpdateResponse`
- New struct `ScopeConnectionsClientDeleteOptions`
- New struct `ScopeConnectionsClientDeleteResponse`
- New struct `ScopeConnectionsClientGetOptions`
- New struct `ScopeConnectionsClientGetResponse`
- New struct `ScopeConnectionsClientListOptions`
- New struct `ScopeConnectionsClientListResponse`
- New struct `SecurityAdminConfiguration`
- New struct `SecurityAdminConfigurationListResult`
- New struct `SecurityAdminConfigurationPropertiesFormat`
- New struct `SecurityAdminConfigurationsClient`
- New struct `SecurityAdminConfigurationsClientBeginDeleteOptions`
- New struct `SecurityAdminConfigurationsClientCreateOrUpdateOptions`
- New struct `SecurityAdminConfigurationsClientCreateOrUpdateResponse`
- New struct `SecurityAdminConfigurationsClientDeleteResponse`
- New struct `SecurityAdminConfigurationsClientGetOptions`
- New struct `SecurityAdminConfigurationsClientGetResponse`
- New struct `SecurityAdminConfigurationsClientListOptions`
- New struct `SecurityAdminConfigurationsClientListResponse`
- New struct `StaticMember`
- New struct `StaticMemberListResult`
- New struct `StaticMemberProperties`
- New struct `StaticMembersClient`
- New struct `StaticMembersClientCreateOrUpdateOptions`
- New struct `StaticMembersClientCreateOrUpdateResponse`
- New struct `StaticMembersClientDeleteOptions`
- New struct `StaticMembersClientDeleteResponse`
- New struct `StaticMembersClientGetOptions`
- New struct `StaticMembersClientGetResponse`
- New struct `StaticMembersClientListOptions`
- New struct `StaticMembersClientListResponse`
- New struct `SubscriptionNetworkManagerConnectionsClient`
- New struct `SubscriptionNetworkManagerConnectionsClientCreateOrUpdateOptions`
- New struct `SubscriptionNetworkManagerConnectionsClientCreateOrUpdateResponse`
- New struct `SubscriptionNetworkManagerConnectionsClientDeleteOptions`
- New struct `SubscriptionNetworkManagerConnectionsClientDeleteResponse`
- New struct `SubscriptionNetworkManagerConnectionsClientGetOptions`
- New struct `SubscriptionNetworkManagerConnectionsClientGetResponse`
- New struct `SubscriptionNetworkManagerConnectionsClientListOptions`
- New struct `SubscriptionNetworkManagerConnectionsClientListResponse`
- New struct `SystemData`
- New struct `VirtualRouterAutoScaleConfiguration`
- New field `NoInternetAdvertise` in struct `CustomIPPrefixPropertiesFormat`
- New field `FlushConnection` in struct `SecurityGroupPropertiesFormat`
- New field `EnablePacFile` in struct `ExplicitProxySettings`
- New field `Scope` in struct `PacketCaptureParameters`
- New field `TargetType` in struct `PacketCaptureParameters`
- New field `Scope` in struct `PacketCaptureResultProperties`
- New field `TargetType` in struct `PacketCaptureResultProperties`
- New field `AutoLearnPrivateRanges` in struct `FirewallPolicySNAT`
- New field `VirtualRouterAutoScaleConfiguration` in struct `VirtualHubProperties`
- New field `Priority` in struct `ApplicationGatewayRoutingRulePropertiesFormat`


## 1.0.0 (2022-05-16)

The package of `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork` is using our [next generation design principles](https://azure.github.io/azure-sdk/general_introduction.html) since version 1.0.0, which contains breaking changes.

To migrate the existing applications to the latest version, please refer to [Migration Guide](https://aka.ms/azsdk/go/mgmt/migration).

To learn more, please refer to our documentation [Quick Start](https://aka.ms/azsdk/go/mgmt).
