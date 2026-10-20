// Copyright 2026 The go-github AUTHORS. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package github

import (
	"context"
	"fmt"
)

// ListRepoVariables lists all Agents variables available in a repository.
//
// GitHub API docs: https://docs.github.com/rest/agents/variables?apiVersion=2026-03-10#list-repository-variables
//
//meta:operation GET /repos/{owner}/{repo}/agents/variables
func (s *AgentsService) ListRepoVariables(ctx context.Context, owner, repo string, opts *ListOptions) (*ActionsVariables, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/agents/variables", owner, repo)
	u, err := addOptions(u, opts)
	if err != nil {
		return nil, nil, err
	}

	req, err := s.client.NewRequest(ctx, "GET", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, nil, err
	}

	var variables *ActionsVariables
	resp, err := s.client.Do(req, &variables)
	if err != nil {
		return nil, resp, err
	}

	return variables, resp, nil
}

// ListRepoOrgVariables lists all organization Agents variables available in a repository.
//
// GitHub API docs: https://docs.github.com/rest/agents/variables?apiVersion=2026-03-10#list-repository-organization-variables
//
//meta:operation GET /repos/{owner}/{repo}/agents/organization-variables
func (s *AgentsService) ListRepoOrgVariables(ctx context.Context, owner, repo string, opts *ListOptions) (*ActionsVariables, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/agents/organization-variables", owner, repo)
	u, err := addOptions(u, opts)
	if err != nil {
		return nil, nil, err
	}

	req, err := s.client.NewRequest(ctx, "GET", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, nil, err
	}

	var variables *ActionsVariables
	resp, err := s.client.Do(req, &variables)
	if err != nil {
		return nil, resp, err
	}

	return variables, resp, nil
}

// ListOrgVariables lists all Agents variables available in an organization.
//
// GitHub API docs: https://docs.github.com/rest/agents/variables?apiVersion=2026-03-10#list-organization-variables
//
//meta:operation GET /orgs/{org}/agents/variables
func (s *AgentsService) ListOrgVariables(ctx context.Context, org string, opts *ListOptions) (*ActionsVariables, *Response, error) {
	u := fmt.Sprintf("orgs/%v/agents/variables", org)
	u, err := addOptions(u, opts)
	if err != nil {
		return nil, nil, err
	}

	req, err := s.client.NewRequest(ctx, "GET", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, nil, err
	}

	var variables *ActionsVariables
	resp, err := s.client.Do(req, &variables)
	if err != nil {
		return nil, resp, err
	}

	return variables, resp, nil
}

// GetRepoVariable gets a single repository Agents variable.
//
// GitHub API docs: https://docs.github.com/rest/agents/variables?apiVersion=2026-03-10#get-a-repository-variable
//
//meta:operation GET /repos/{owner}/{repo}/agents/variables/{name}
func (s *AgentsService) GetRepoVariable(ctx context.Context, owner, repo, name string) (*ActionsVariable, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/agents/variables/%v", owner, repo, name)

	req, err := s.client.NewRequest(ctx, "GET", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, nil, err
	}

	var variable *ActionsVariable
	resp, err := s.client.Do(req, &variable)
	if err != nil {
		return nil, resp, err
	}

	return variable, resp, nil
}

// GetOrgVariable gets a single organization Agents variable.
//
// GitHub API docs: https://docs.github.com/rest/agents/variables?apiVersion=2026-03-10#get-an-organization-variable
//
//meta:operation GET /orgs/{org}/agents/variables/{name}
func (s *AgentsService) GetOrgVariable(ctx context.Context, org, name string) (*ActionsVariable, *Response, error) {
	u := fmt.Sprintf("orgs/%v/agents/variables/%v", org, name)

	req, err := s.client.NewRequest(ctx, "GET", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, nil, err
	}

	var variable *ActionsVariable
	resp, err := s.client.Do(req, &variable)
	if err != nil {
		return nil, resp, err
	}

	return variable, resp, nil
}

// CreateRepoVariable creates a repository Agents variable.
//
// GitHub API docs: https://docs.github.com/rest/agents/variables?apiVersion=2026-03-10#create-a-repository-variable
//
//meta:operation POST /repos/{owner}/{repo}/agents/variables
func (s *AgentsService) CreateRepoVariable(ctx context.Context, owner, repo string, body ActionsCreateVariableRequest) (*Response, error) {
	u := fmt.Sprintf("repos/%v/%v/agents/variables", owner, repo)

	req, err := s.client.NewRequest(ctx, "POST", u, body, WithVersion(api20260310))
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// CreateOrgVariable creates an organization Agents variable.
//
// GitHub API docs: https://docs.github.com/rest/agents/variables?apiVersion=2026-03-10#create-an-organization-variable
//
//meta:operation POST /orgs/{org}/agents/variables
func (s *AgentsService) CreateOrgVariable(ctx context.Context, org string, body ActionsCreateOrgVariableRequest) (*Response, error) {
	u := fmt.Sprintf("orgs/%v/agents/variables", org)

	req, err := s.client.NewRequest(ctx, "POST", u, body, WithVersion(api20260310))
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// UpdateRepoVariable updates a repository Agents variable.
//
// GitHub API docs: https://docs.github.com/rest/agents/variables?apiVersion=2026-03-10#update-a-repository-variable
//
//meta:operation PATCH /repos/{owner}/{repo}/agents/variables/{name}
func (s *AgentsService) UpdateRepoVariable(ctx context.Context, owner, repo, name string, body ActionsUpdateVariableRequest) (*Response, error) {
	u := fmt.Sprintf("repos/%v/%v/agents/variables/%v", owner, repo, name)

	req, err := s.client.NewRequest(ctx, "PATCH", u, body, WithVersion(api20260310))
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// UpdateOrgVariable updates an organization Agents variable.
//
// GitHub API docs: https://docs.github.com/rest/agents/variables?apiVersion=2026-03-10#update-an-organization-variable
//
//meta:operation PATCH /orgs/{org}/agents/variables/{name}
func (s *AgentsService) UpdateOrgVariable(ctx context.Context, org, name string, body ActionsUpdateOrgVariableRequest) (*Response, error) {
	u := fmt.Sprintf("orgs/%v/agents/variables/%v", org, name)

	req, err := s.client.NewRequest(ctx, "PATCH", u, body, WithVersion(api20260310))
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// DeleteRepoVariable deletes a repository Agents variable using the variable name.
//
// GitHub API docs: https://docs.github.com/rest/agents/variables?apiVersion=2026-03-10#delete-a-repository-variable
//
//meta:operation DELETE /repos/{owner}/{repo}/agents/variables/{name}
func (s *AgentsService) DeleteRepoVariable(ctx context.Context, owner, repo, name string) (*Response, error) {
	u := fmt.Sprintf("repos/%v/%v/agents/variables/%v", owner, repo, name)

	req, err := s.client.NewRequest(ctx, "DELETE", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// DeleteOrgVariable deletes an organization Agents variable using the variable name.
//
// GitHub API docs: https://docs.github.com/rest/agents/variables?apiVersion=2026-03-10#delete-an-organization-variable
//
//meta:operation DELETE /orgs/{org}/agents/variables/{name}
func (s *AgentsService) DeleteOrgVariable(ctx context.Context, org, name string) (*Response, error) {
	u := fmt.Sprintf("orgs/%v/agents/variables/%v", org, name)

	req, err := s.client.NewRequest(ctx, "DELETE", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// ListSelectedReposForOrgVariable lists all repositories that have access to an organization Agents variable.
//
// GitHub API docs: https://docs.github.com/rest/agents/variables?apiVersion=2026-03-10#list-selected-repositories-for-an-organization-variable
//
//meta:operation GET /orgs/{org}/agents/variables/{name}/repositories
func (s *AgentsService) ListSelectedReposForOrgVariable(ctx context.Context, org, name string, opts *ListOptions) (*SelectedReposList, *Response, error) {
	u := fmt.Sprintf("orgs/%v/agents/variables/%v/repositories", org, name)
	u, err := addOptions(u, opts)
	if err != nil {
		return nil, nil, err
	}

	req, err := s.client.NewRequest(ctx, "GET", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, nil, err
	}

	var result *SelectedReposList
	resp, err := s.client.Do(req, &result)
	if err != nil {
		return nil, resp, err
	}

	return result, resp, nil
}

// SetSelectedReposForOrgVariable sets the repositories that have access to an organization Agents variable.
//
// GitHub API docs: https://docs.github.com/rest/agents/variables?apiVersion=2026-03-10#set-selected-repositories-for-an-organization-variable
//
//meta:operation PUT /orgs/{org}/agents/variables/{name}/repositories
func (s *AgentsService) SetSelectedReposForOrgVariable(ctx context.Context, org, name string, ids []int64) (*Response, error) {
	u := fmt.Sprintf("orgs/%v/agents/variables/%v/repositories", org, name)

	type repoIDs struct {
		SelectedIDs []int64 `json:"selected_repository_ids"`
	}

	req, err := s.client.NewRequest(ctx, "PUT", u, repoIDs{SelectedIDs: ids}, WithVersion(api20260310))
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// AddSelectedRepoToOrgVariable adds a repository to an organization Agents variable.
//
// GitHub API docs: https://docs.github.com/rest/agents/variables?apiVersion=2026-03-10#add-selected-repository-to-an-organization-variable
//
//meta:operation PUT /orgs/{org}/agents/variables/{name}/repositories/{repository_id}
func (s *AgentsService) AddSelectedRepoToOrgVariable(ctx context.Context, org, name string, repoID int64) (*Response, error) {
	u := fmt.Sprintf("orgs/%v/agents/variables/%v/repositories/%v", org, name, repoID)

	req, err := s.client.NewRequest(ctx, "PUT", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// RemoveSelectedRepoFromOrgVariable removes a repository from an organization Agents variable.
//
// GitHub API docs: https://docs.github.com/rest/agents/variables?apiVersion=2026-03-10#remove-selected-repository-from-an-organization-variable
//
//meta:operation DELETE /orgs/{org}/agents/variables/{name}/repositories/{repository_id}
func (s *AgentsService) RemoveSelectedRepoFromOrgVariable(ctx context.Context, org, name string, repoID int64) (*Response, error) {
	u := fmt.Sprintf("orgs/%v/agents/variables/%v/repositories/%v", org, name, repoID)

	req, err := s.client.NewRequest(ctx, "DELETE", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}
