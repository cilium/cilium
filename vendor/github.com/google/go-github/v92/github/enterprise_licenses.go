// Copyright 2025 The go-github AUTHORS. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package github

import (
	"context"
	"fmt"
)

// EnterpriseConsumedLicenses represents information about users with consumed enterprise licenses.
type EnterpriseConsumedLicenses struct {
	TotalSeatsConsumed  int                        `json:"total_seats_consumed"`
	TotalSeatsPurchased int                        `json:"total_seats_purchased"`
	Users               []*EnterpriseLicensedUsers `json:"users,omitempty"`
}

// EnterpriseLicensedUsers represents a user with license information in an enterprise.
type EnterpriseLicensedUsers struct {
	GithubComLogin                  string   `json:"github_com_login"`
	GithubComName                   *string  `json:"github_com_name"`
	EnterpriseServerUserIDs         []string `json:"enterprise_server_user_ids,omitempty"`
	GithubComUser                   bool     `json:"github_com_user"`
	EnterpriseServerUser            *bool    `json:"enterprise_server_user"`
	VisualStudioSubscriptionUser    bool     `json:"visual_studio_subscription_user"`
	LicenseType                     string   `json:"license_type"`
	GithubComProfile                *string  `json:"github_com_profile"`
	GithubComMemberRoles            []string `json:"github_com_member_roles,omitempty"`
	GithubComEnterpriseRoles        []string `json:"github_com_enterprise_roles,omitempty"`
	GithubComVerifiedDomainEmails   []string `json:"github_com_verified_domain_emails,omitempty"`
	GithubComSamlNameID             *string  `json:"github_com_saml_name_id"`
	GithubComOrgsWithPendingInvites []string `json:"github_com_orgs_with_pending_invites,omitempty"`
	GithubComTwoFactorAuth          *bool    `json:"github_com_two_factor_auth"`
	EnterpriseServerEmails          []string `json:"enterprise_server_emails,omitempty"`
	VisualStudioLicenseStatus       *string  `json:"visual_studio_license_status"`
	VisualStudioSubscriptionEmail   *string  `json:"visual_studio_subscription_email"`
	TotalUserAccounts               int      `json:"total_user_accounts"`
}

// EnterpriseLicenseSyncStatus represents the synchronization status of
// GitHub Enterprise Server instances with an enterprise account.
type EnterpriseLicenseSyncStatus struct {
	Title       string                    `json:"title"`
	Description string                    `json:"description"`
	Properties  *ServerInstanceProperties `json:"properties,omitempty"`
}

// ServerInstanceProperties contains the collection of server instances.
type ServerInstanceProperties struct {
	ServerInstances *ServerInstances `json:"server_instances,omitempty"`
}

// ServerInstances represents a collection of GitHub Enterprise Server instances
// and their synchronization status.
type ServerInstances struct {
	Type  string                `json:"type"`
	Items *ServiceInstanceItems `json:"items,omitempty"`
}

// ServiceInstanceItems defines the structure and properties of individual server instances
// in the collection.
type ServiceInstanceItems struct {
	Type       string                `json:"type"`
	Properties *ServerItemProperties `json:"properties,omitempty"`
}

// ServerItemProperties represents the properties of a GitHub Enterprise Server instance,
// including its identifier, hostname, and last synchronization status.
type ServerItemProperties struct {
	ServerID string           `json:"server_id"`
	Hostname string           `json:"hostname"`
	LastSync *LastLicenseSync `json:"last_sync,omitempty"`
}

// LastLicenseSync contains information about the most recent license synchronization
// attempt for a server instance.
type LastLicenseSync struct {
	Type       string                     `json:"type"`
	Properties *LastLicenseSyncProperties `json:"properties,omitempty"`
}

// LastLicenseSyncProperties represents the details of the last synchronization attempt,
// including the date, status, and any error that occurred.
type LastLicenseSyncProperties struct {
	Date   *Timestamp `json:"date,omitempty"`
	Status string     `json:"status"`
	Error  string     `json:"error"`
}

// VisualStudioSubscriptionAssignment represents a user's Visual Studio subscription assignment.
type VisualStudioSubscriptionAssignment struct {
	VisualStudioSubscriptionEmail *string `json:"visual_studio_subscription_email,omitempty"`
	SubscriptionID                *string `json:"subscription_id,omitempty"`
	Username                      *string `json:"username,omitempty"`
	ManualMatch                   *bool   `json:"manual_match,omitempty"`
}

// VisualStudioSubscriptions represents a list of Visual Studio subscriptions for an enterprise.
type VisualStudioSubscriptions struct {
	TotalCount                *int                                  `json:"total_count,omitempty"`
	VisualStudioSubscriptions []*VisualStudioSubscriptionAssignment `json:"visual_studio_subscriptions,omitempty"`
}

// VisualStudioSubscriptionAssignmentRequest represents the request body to add or update a subscription assignment.
type VisualStudioSubscriptionAssignmentRequest struct {
	UserIdentifier *string `json:"user_identifier,omitempty"`
}

// ListVisualStudioSubscriptionsOptions specifies the optional parameters to
// EnterpriseService.ListVisualStudioSubscriptions.
type ListVisualStudioSubscriptionsOptions struct {
	ListOptions

	// IsUnmatchedOnly filters results to return only unmatched subscriptions.
	IsUnmatchedOnly bool `url:"is_unmatched_only,omitempty"`
}

// ListConsumedLicenses collect information about the number of consumed licenses and a collection with all the users with consumed enterprise licenses.
//
// GitHub API docs: https://docs.github.com/enterprise-cloud@latest/rest/enterprise-admin/licensing?apiVersion=2022-11-28#list-enterprise-consumed-licenses
//
//meta:operation GET /enterprises/{enterprise}/consumed-licenses
func (s *EnterpriseService) ListConsumedLicenses(ctx context.Context, enterprise string, opts *ListOptions) (*EnterpriseConsumedLicenses, *Response, error) {
	u := fmt.Sprintf("enterprises/%v/consumed-licenses", enterprise)
	u, err := addOptions(u, opts)
	if err != nil {
		return nil, nil, err
	}

	req, err := s.client.NewRequest(ctx, "GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	var consumedLicenses *EnterpriseConsumedLicenses
	resp, err := s.client.Do(req, &consumedLicenses)
	if err != nil {
		return nil, resp, err
	}

	return consumedLicenses, resp, nil
}

// GetLicenseSyncStatus collects information about the status of a license sync job for an enterprise.
//
// GitHub API docs: https://docs.github.com/enterprise-cloud@latest/rest/enterprise-admin/licensing?apiVersion=2022-11-28#get-a-license-sync-status
//
//meta:operation GET /enterprises/{enterprise}/license-sync-status
func (s *EnterpriseService) GetLicenseSyncStatus(ctx context.Context, enterprise string) (*EnterpriseLicenseSyncStatus, *Response, error) {
	u := fmt.Sprintf("enterprises/%v/license-sync-status", enterprise)

	req, err := s.client.NewRequest(ctx, "GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	var syncStatus *EnterpriseLicenseSyncStatus
	resp, err := s.client.Do(req, &syncStatus)
	if err != nil {
		return nil, resp, err
	}

	return syncStatus, resp, nil
}

// ListVisualStudioSubscriptions gets a list of Visual Studio subscriptions for an enterprise.
//
// GitHub API docs: https://docs.github.com/enterprise-cloud@latest/rest/enterprise-admin/licensing?apiVersion=2022-11-28#get-a-list-of-visual-studio-subscriptions-for-the-enterprise
//
//meta:operation GET /enterprises/{enterprise}/visual-studio-subscriptions
func (s *EnterpriseService) ListVisualStudioSubscriptions(ctx context.Context, enterprise string, opts *ListVisualStudioSubscriptionsOptions) (*VisualStudioSubscriptions, *Response, error) {
	u := fmt.Sprintf("enterprises/%v/visual-studio-subscriptions", enterprise)
	u, err := addOptions(u, opts)
	if err != nil {
		return nil, nil, err
	}

	req, err := s.client.NewRequest(ctx, "GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	var subscriptions *VisualStudioSubscriptions
	resp, err := s.client.Do(req, &subscriptions)
	if err != nil {
		return nil, resp, err
	}

	return subscriptions, resp, nil
}

// AddOrUpdateVisualStudioSubscriptionAssignment adds or updates a manual match between a user and a Visual Studio subscription.
//
// GitHub API docs: https://docs.github.com/enterprise-cloud@latest/rest/enterprise-admin/licensing?apiVersion=2022-11-28#add-or-update-a-visual-studio-subscription-user-match
//
//meta:operation PUT /enterprises/{enterprise}/visual-studio-subscriptions/{visual_studio_subscription_id}
func (s *EnterpriseService) AddOrUpdateVisualStudioSubscriptionAssignment(ctx context.Context, enterprise, subscriptionID string, body VisualStudioSubscriptionAssignmentRequest) (*VisualStudioSubscriptionAssignment, *Response, error) {
	u := fmt.Sprintf("enterprises/%v/visual-studio-subscriptions/%v", enterprise, subscriptionID)

	req, err := s.client.NewRequest(ctx, "PUT", u, body)
	if err != nil {
		return nil, nil, err
	}

	var assignment *VisualStudioSubscriptionAssignment
	resp, err := s.client.Do(req, &assignment)
	if err != nil {
		return nil, resp, err
	}

	return assignment, resp, nil
}

// DeleteVisualStudioSubscriptionAssignment deletes a manual match between a user and a Visual Studio subscription.
//
// GitHub API docs: https://docs.github.com/enterprise-cloud@latest/rest/enterprise-admin/licensing?apiVersion=2022-11-28#delete-a-visual-studio-subscription-user-match
//
//meta:operation DELETE /enterprises/{enterprise}/visual-studio-subscriptions/{visual_studio_subscription_id}
func (s *EnterpriseService) DeleteVisualStudioSubscriptionAssignment(ctx context.Context, enterprise, subscriptionID string) (*Response, error) {
	u := fmt.Sprintf("enterprises/%v/visual-studio-subscriptions/%v", enterprise, subscriptionID)

	req, err := s.client.NewRequest(ctx, "DELETE", u, nil)
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}
