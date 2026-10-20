// Copyright 2026 The go-github AUTHORS. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package github

import (
	"context"
	"fmt"
)

// ActionsPolicyTarget represents a GitHub Actions policy target.
type ActionsPolicyTarget string

// ActionsPolicyTargetActions is the target used by GitHub Actions policies.
const ActionsPolicyTargetActions ActionsPolicyTarget = "actions"

// ActionsPolicyRuleType represents a GitHub Actions policy rule type.
type ActionsPolicyRuleType string

// GitHub Actions policy rule types.
const (
	ActionsPolicyRuleTypeRestrictActionsActors ActionsPolicyRuleType = "restrict_actions_actors"
	ActionsPolicyRuleTypeRestrictActionEvents  ActionsPolicyRuleType = "restrict_action_events"
)

// ActionsPolicyActorType represents the type of an actor allowed to trigger Actions workflows.
type ActionsPolicyActorType string

// GitHub Actions policy actor types.
const (
	ActionsPolicyActorTypeUser                    ActionsPolicyActorType = "User"
	ActionsPolicyActorTypeBot                     ActionsPolicyActorType = "Bot"
	ActionsPolicyActorTypeTeam                    ActionsPolicyActorType = "Team"
	ActionsPolicyActorTypeBusinessTeam            ActionsPolicyActorType = "BusinessTeam"
	ActionsPolicyActorTypeEnterpriseTeam          ActionsPolicyActorType = "EnterpriseTeam"
	ActionsPolicyActorTypeIntegrationInstallation ActionsPolicyActorType = "IntegrationInstallation"
	ActionsPolicyActorTypeApp                     ActionsPolicyActorType = "App"
	ActionsPolicyActorTypeRepositoryRole          ActionsPolicyActorType = "RepositoryRole"
)

// ActionsPolicy represents a GitHub Actions policy.
//
// GitHub API docs: https://docs.github.com/rest/actions/policies?apiVersion=2026-03-10
type ActionsPolicy struct {
	ID          int64                    `json:"id"`
	Name        string                   `json:"name"`
	Target      ActionsPolicyTarget      `json:"target"`
	SourceType  RulesetSourceType        `json:"source_type"`
	Source      string                   `json:"source"`
	Enforcement RulesetEnforcement       `json:"enforcement"`
	Conditions  *ActionsPolicyConditions `json:"conditions,omitempty"`
	Rules       []*ActionsPolicyRule     `json:"rules,omitzero"`
	NodeID      *string                  `json:"node_id,omitempty"`
	Links       *RepositoryRulesetLinks  `json:"_links,omitempty"`
	CreatedAt   *Timestamp               `json:"created_at,omitempty"`
	UpdatedAt   *Timestamp               `json:"updated_at,omitempty"`
}

// CreateActionsPolicyRequest represents a request to create a GitHub Actions policy.
type CreateActionsPolicyRequest struct {
	Name        string                   `json:"name"`
	Enforcement RulesetEnforcement       `json:"enforcement"`
	Conditions  *ActionsPolicyConditions `json:"conditions,omitempty"`
	Rules       []*ActionsPolicyRule     `json:"rules,omitzero"`
}

// UpdateActionsPolicyRequest represents a request to update a GitHub Actions policy.
type UpdateActionsPolicyRequest struct {
	Name        *string                  `json:"name,omitempty"`
	Enforcement *RulesetEnforcement      `json:"enforcement,omitempty"`
	Conditions  *ActionsPolicyConditions `json:"conditions,omitempty"`
	Rules       []*ActionsPolicyRule     `json:"rules,omitzero"`
}

// ActionsPolicyConditions represents the conditions object in an Actions policy.
// Organization policies may use one repository selector and an optional workflow path selector.
// Policies inherited from higher levels can also contain organization selectors.
type ActionsPolicyConditions struct {
	RepositoryID         *RepositoryRulesetRepositoryIDsConditionParameters        `json:"repository_id,omitempty"`
	RepositoryName       *RepositoryRulesetRepositoryNamesConditionParameters      `json:"repository_name,omitempty"`
	RepositoryProperty   *RepositoryRulesetRepositoryPropertyConditionParameters   `json:"repository_property,omitempty"`
	OrganizationID       *RepositoryRulesetOrganizationIDsConditionParameters      `json:"organization_id,omitempty"`
	OrganizationName     *RepositoryRulesetOrganizationNamesConditionParameters    `json:"organization_name,omitempty"`
	OrganizationProperty *RepositoryRulesetOrganizationPropertyConditionParameters `json:"organization_property,omitempty"`
	WorkflowPath         *ActionsPolicyWorkflowPathConditionParameters             `json:"workflow_path,omitempty"`
}

// ActionsPolicyWorkflowPathConditionParameters represents a workflow_path condition in an Actions policy.
type ActionsPolicyWorkflowPathConditionParameters struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

// ActionsPolicyRule represents a rule in an Actions policy.
type ActionsPolicyRule struct {
	Type       ActionsPolicyRuleType        `json:"type"`
	Parameters *ActionsPolicyRuleParameters `json:"parameters,omitempty"`
}

// ActionsPolicyRuleParameters represents the parameters for an Actions policy rule.
// AllowedActors is used by restrict_actions_actors; AllowedEvents is used by restrict_action_events.
type ActionsPolicyRuleParameters struct {
	AllowedActors []*ActionsPolicyActor `json:"allowed_actors,omitzero"`
	AllowedEvents []string              `json:"allowed_events,omitzero"`
}

// ActionsPolicyActor represents an actor authorized to trigger Actions workflows.
type ActionsPolicyActor struct {
	ID   int64                  `json:"id"`
	Type ActionsPolicyActorType `json:"type"`
}

// ActionsPolicyList represents a list of GitHub Actions policies.
type ActionsPolicyList struct {
	TotalCount int              `json:"total_count"`
	Policies   []*ActionsPolicy `json:"policies"`
}

// ActionsPolicyListOptions specifies optional parameters for listing Actions policies.
type ActionsPolicyListOptions struct {
	// HasParents controls whether policies configured at higher levels are included.
	HasParents *bool `url:"has_parents,omitempty"`
	ListOptions
}

func (s *ActionsService) listPolicies(ctx context.Context, u string, opts *ActionsPolicyListOptions) (*ActionsPolicyList, *Response, error) {
	u, err := addOptions(u, opts)
	if err != nil {
		return nil, nil, err
	}

	req, err := s.client.NewRequest(ctx, "GET", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, nil, err
	}

	var policies *ActionsPolicyList
	resp, err := s.client.Do(req, &policies)
	if err != nil {
		return nil, resp, err
	}

	return policies, resp, nil
}

func (s *ActionsService) createPolicy(ctx context.Context, u string, body CreateActionsPolicyRequest) (*ActionsPolicy, *Response, error) {
	req, err := s.client.NewRequest(ctx, "POST", u, body, WithVersion(api20260310))
	if err != nil {
		return nil, nil, err
	}

	var policy *ActionsPolicy
	resp, err := s.client.Do(req, &policy)
	if err != nil {
		return nil, resp, err
	}

	return policy, resp, nil
}

func (s *ActionsService) getPolicy(ctx context.Context, u string) (*ActionsPolicy, *Response, error) {
	req, err := s.client.NewRequest(ctx, "GET", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, nil, err
	}

	var policy *ActionsPolicy
	resp, err := s.client.Do(req, &policy)
	if err != nil {
		return nil, resp, err
	}

	return policy, resp, nil
}

func (s *ActionsService) updatePolicy(ctx context.Context, u string, body UpdateActionsPolicyRequest) (*ActionsPolicy, *Response, error) {
	req, err := s.client.NewRequest(ctx, "PUT", u, body, WithVersion(api20260310))
	if err != nil {
		return nil, nil, err
	}

	var policy *ActionsPolicy
	resp, err := s.client.Do(req, &policy)
	if err != nil {
		return nil, resp, err
	}

	return policy, resp, nil
}

func (s *ActionsService) deletePolicy(ctx context.Context, u string) (*Response, error) {
	req, err := s.client.NewRequest(ctx, "DELETE", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, err
	}
	return s.client.Do(req, nil)
}

// ListOrganizationPolicies lists all Actions policies for an organization.
//
// GitHub API docs: https://docs.github.com/rest/actions/policies?apiVersion=2026-03-10#list-organization-actions-policies
//
//meta:operation GET /orgs/{org}/actions/policies
func (s *ActionsService) ListOrganizationPolicies(ctx context.Context, org string, opts *ActionsPolicyListOptions) (*ActionsPolicyList, *Response, error) {
	u := fmt.Sprintf("orgs/%v/actions/policies", org)
	return s.listPolicies(ctx, u, opts)
}

// CreateOrganizationPolicy creates an Actions policy for an organization.
//
// GitHub API docs: https://docs.github.com/rest/actions/policies?apiVersion=2026-03-10#create-an-organization-actions-policy
//
//meta:operation POST /orgs/{org}/actions/policies
func (s *ActionsService) CreateOrganizationPolicy(ctx context.Context, org string, body CreateActionsPolicyRequest) (*ActionsPolicy, *Response, error) {
	u := fmt.Sprintf("orgs/%v/actions/policies", org)
	return s.createPolicy(ctx, u, body)
}

// GetOrganizationPolicy gets a specific Actions policy for an organization.
//
// GitHub API docs: https://docs.github.com/rest/actions/policies?apiVersion=2026-03-10#get-an-organization-actions-policy
//
//meta:operation GET /orgs/{org}/actions/policies/{policy_id}
func (s *ActionsService) GetOrganizationPolicy(ctx context.Context, org string, policyID int64) (*ActionsPolicy, *Response, error) {
	u := fmt.Sprintf("orgs/%v/actions/policies/%v", org, policyID)
	return s.getPolicy(ctx, u)
}

// UpdateOrganizationPolicy updates an Actions policy for an organization.
//
// GitHub API docs: https://docs.github.com/rest/actions/policies?apiVersion=2026-03-10#update-an-organization-actions-policy
//
//meta:operation PUT /orgs/{org}/actions/policies/{policy_id}
func (s *ActionsService) UpdateOrganizationPolicy(ctx context.Context, org string, policyID int64, body UpdateActionsPolicyRequest) (*ActionsPolicy, *Response, error) {
	u := fmt.Sprintf("orgs/%v/actions/policies/%v", org, policyID)
	return s.updatePolicy(ctx, u, body)
}

// DeleteOrganizationPolicy deletes an Actions policy for an organization.
//
// GitHub API docs: https://docs.github.com/rest/actions/policies?apiVersion=2026-03-10#delete-an-organization-actions-policy
//
//meta:operation DELETE /orgs/{org}/actions/policies/{policy_id}
func (s *ActionsService) DeleteOrganizationPolicy(ctx context.Context, org string, policyID int64) (*Response, error) {
	u := fmt.Sprintf("orgs/%v/actions/policies/%v", org, policyID)
	return s.deletePolicy(ctx, u)
}

// ListRepositoryPolicies lists all Actions policies for a repository.
//
// GitHub API docs: https://docs.github.com/rest/actions/policies?apiVersion=2026-03-10#list-repository-actions-policies
//
//meta:operation GET /repos/{owner}/{repo}/actions/policies
func (s *ActionsService) ListRepositoryPolicies(ctx context.Context, owner, repo string, opts *ActionsPolicyListOptions) (*ActionsPolicyList, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/actions/policies", owner, repo)
	return s.listPolicies(ctx, u, opts)
}

// CreateRepositoryPolicy creates an Actions policy for a repository.
//
// GitHub API docs: https://docs.github.com/rest/actions/policies?apiVersion=2026-03-10#create-a-repository-actions-policy
//
//meta:operation POST /repos/{owner}/{repo}/actions/policies
func (s *ActionsService) CreateRepositoryPolicy(ctx context.Context, owner, repo string, body CreateActionsPolicyRequest) (*ActionsPolicy, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/actions/policies", owner, repo)
	return s.createPolicy(ctx, u, body)
}

// GetRepositoryPolicy gets a specific Actions policy for a repository.
//
// GitHub API docs: https://docs.github.com/rest/actions/policies?apiVersion=2026-03-10#get-a-repository-actions-policy
//
//meta:operation GET /repos/{owner}/{repo}/actions/policies/{policy_id}
func (s *ActionsService) GetRepositoryPolicy(ctx context.Context, owner, repo string, policyID int64) (*ActionsPolicy, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/actions/policies/%v", owner, repo, policyID)
	return s.getPolicy(ctx, u)
}

// UpdateRepositoryPolicy updates an Actions policy for a repository.
//
// GitHub API docs: https://docs.github.com/rest/actions/policies?apiVersion=2026-03-10#update-a-repository-actions-policy
//
//meta:operation PUT /repos/{owner}/{repo}/actions/policies/{policy_id}
func (s *ActionsService) UpdateRepositoryPolicy(ctx context.Context, owner, repo string, policyID int64, body UpdateActionsPolicyRequest) (*ActionsPolicy, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/actions/policies/%v", owner, repo, policyID)
	return s.updatePolicy(ctx, u, body)
}

// DeleteRepositoryPolicy deletes an Actions policy for a repository.
//
// GitHub API docs: https://docs.github.com/rest/actions/policies?apiVersion=2026-03-10#delete-a-repository-actions-policy
//
//meta:operation DELETE /repos/{owner}/{repo}/actions/policies/{policy_id}
func (s *ActionsService) DeleteRepositoryPolicy(ctx context.Context, owner, repo string, policyID int64) (*Response, error) {
	u := fmt.Sprintf("repos/%v/%v/actions/policies/%v", owner, repo, policyID)
	return s.deletePolicy(ctx, u)
}
