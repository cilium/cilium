// Copyright 2026 The go-github AUTHORS. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package github

import (
	"context"
	"fmt"
)

// GetRepoPublicKey gets a public key that should be used for Agents secret encryption.
//
// GitHub API docs: https://docs.github.com/rest/agents/secrets?apiVersion=2026-03-10#get-a-repository-public-key
//
//meta:operation GET /repos/{owner}/{repo}/agents/secrets/public-key
func (s *AgentsService) GetRepoPublicKey(ctx context.Context, owner, repo string) (*PublicKey, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/agents/secrets/public-key", owner, repo)

	req, err := s.client.NewRequest(ctx, "GET", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, nil, err
	}

	var pubKey *PublicKey
	resp, err := s.client.Do(req, &pubKey)
	if err != nil {
		return nil, resp, err
	}

	return pubKey, resp, nil
}

// GetOrgPublicKey gets a public key that should be used for Agents secret encryption.
//
// GitHub API docs: https://docs.github.com/rest/agents/secrets?apiVersion=2026-03-10#get-an-organization-public-key
//
//meta:operation GET /orgs/{org}/agents/secrets/public-key
func (s *AgentsService) GetOrgPublicKey(ctx context.Context, org string) (*PublicKey, *Response, error) {
	u := fmt.Sprintf("orgs/%v/agents/secrets/public-key", org)

	req, err := s.client.NewRequest(ctx, "GET", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, nil, err
	}

	var pubKey *PublicKey
	resp, err := s.client.Do(req, &pubKey)
	if err != nil {
		return nil, resp, err
	}

	return pubKey, resp, nil
}

// ListRepoSecrets lists all Agents secrets available in a repository
// without revealing their encrypted values.
//
// GitHub API docs: https://docs.github.com/rest/agents/secrets?apiVersion=2026-03-10#list-repository-secrets
//
//meta:operation GET /repos/{owner}/{repo}/agents/secrets
func (s *AgentsService) ListRepoSecrets(ctx context.Context, owner, repo string, opts *ListOptions) (*Secrets, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/agents/secrets", owner, repo)
	u, err := addOptions(u, opts)
	if err != nil {
		return nil, nil, err
	}

	req, err := s.client.NewRequest(ctx, "GET", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, nil, err
	}

	var secrets *Secrets
	resp, err := s.client.Do(req, &secrets)
	if err != nil {
		return nil, resp, err
	}

	return secrets, resp, nil
}

// ListOrgSecrets lists all Agents secrets available in an organization
// without revealing their encrypted values.
//
// GitHub API docs: https://docs.github.com/rest/agents/secrets?apiVersion=2026-03-10#list-organization-secrets
//
//meta:operation GET /orgs/{org}/agents/secrets
func (s *AgentsService) ListOrgSecrets(ctx context.Context, org string, opts *ListOptions) (*Secrets, *Response, error) {
	u := fmt.Sprintf("orgs/%v/agents/secrets", org)
	u, err := addOptions(u, opts)
	if err != nil {
		return nil, nil, err
	}

	req, err := s.client.NewRequest(ctx, "GET", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, nil, err
	}

	var secrets *Secrets
	resp, err := s.client.Do(req, &secrets)
	if err != nil {
		return nil, resp, err
	}

	return secrets, resp, nil
}

// ListRepoOrgSecrets lists all organization Agents secrets available in a repository
// without revealing their encrypted values.
//
// GitHub API docs: https://docs.github.com/rest/agents/secrets?apiVersion=2026-03-10#list-repository-organization-secrets
//
//meta:operation GET /repos/{owner}/{repo}/agents/organization-secrets
func (s *AgentsService) ListRepoOrgSecrets(ctx context.Context, owner, repo string, opts *ListOptions) (*Secrets, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/agents/organization-secrets", owner, repo)
	u, err := addOptions(u, opts)
	if err != nil {
		return nil, nil, err
	}

	req, err := s.client.NewRequest(ctx, "GET", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, nil, err
	}

	var secrets *Secrets
	resp, err := s.client.Do(req, &secrets)
	if err != nil {
		return nil, resp, err
	}

	return secrets, resp, nil
}

// GetRepoSecret gets a single repository Agents secret without revealing its encrypted value.
//
// GitHub API docs: https://docs.github.com/rest/agents/secrets?apiVersion=2026-03-10#get-a-repository-secret
//
//meta:operation GET /repos/{owner}/{repo}/agents/secrets/{secret_name}
func (s *AgentsService) GetRepoSecret(ctx context.Context, owner, repo, name string) (*Secret, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/agents/secrets/%v", owner, repo, name)

	req, err := s.client.NewRequest(ctx, "GET", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, nil, err
	}

	var secret *Secret
	resp, err := s.client.Do(req, &secret)
	if err != nil {
		return nil, resp, err
	}

	return secret, resp, nil
}

// GetOrgSecret gets a single organization Agents secret without revealing its encrypted value.
//
// GitHub API docs: https://docs.github.com/rest/agents/secrets?apiVersion=2026-03-10#get-an-organization-secret
//
//meta:operation GET /orgs/{org}/agents/secrets/{secret_name}
func (s *AgentsService) GetOrgSecret(ctx context.Context, org, name string) (*Secret, *Response, error) {
	u := fmt.Sprintf("orgs/%v/agents/secrets/%v", org, name)

	req, err := s.client.NewRequest(ctx, "GET", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, nil, err
	}

	var secret *Secret
	resp, err := s.client.Do(req, &secret)
	if err != nil {
		return nil, resp, err
	}

	return secret, resp, nil
}

// CreateOrUpdateRepoSecret creates or updates a repository Agents secret with an encrypted value.
//
// GitHub API docs: https://docs.github.com/rest/agents/secrets?apiVersion=2026-03-10#create-or-update-a-repository-secret
//
//meta:operation PUT /repos/{owner}/{repo}/agents/secrets/{secret_name}
func (s *AgentsService) CreateOrUpdateRepoSecret(ctx context.Context, owner, repo, name string, body SecretRequest) (*Response, error) {
	u := fmt.Sprintf("repos/%v/%v/agents/secrets/%v", owner, repo, name)

	req, err := s.client.NewRequest(ctx, "PUT", u, body, WithVersion(api20260310))
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// CreateOrUpdateOrgSecret creates or updates an organization Agents secret with an encrypted value.
//
// GitHub API docs: https://docs.github.com/rest/agents/secrets?apiVersion=2026-03-10#create-or-update-an-organization-secret
//
//meta:operation PUT /orgs/{org}/agents/secrets/{secret_name}
func (s *AgentsService) CreateOrUpdateOrgSecret(ctx context.Context, org, name string, body SecretOrgRequest) (*Response, error) {
	u := fmt.Sprintf("orgs/%v/agents/secrets/%v", org, name)

	req, err := s.client.NewRequest(ctx, "PUT", u, body, WithVersion(api20260310))
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// DeleteRepoSecret deletes an Agents secret in a repository using the secret name.
//
// GitHub API docs: https://docs.github.com/rest/agents/secrets?apiVersion=2026-03-10#delete-a-repository-secret
//
//meta:operation DELETE /repos/{owner}/{repo}/agents/secrets/{secret_name}
func (s *AgentsService) DeleteRepoSecret(ctx context.Context, owner, repo, name string) (*Response, error) {
	u := fmt.Sprintf("repos/%v/%v/agents/secrets/%v", owner, repo, name)

	req, err := s.client.NewRequest(ctx, "DELETE", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// DeleteOrgSecret deletes an Agents secret in an organization using the secret name.
//
// GitHub API docs: https://docs.github.com/rest/agents/secrets?apiVersion=2026-03-10#delete-an-organization-secret
//
//meta:operation DELETE /orgs/{org}/agents/secrets/{secret_name}
func (s *AgentsService) DeleteOrgSecret(ctx context.Context, org, name string) (*Response, error) {
	u := fmt.Sprintf("orgs/%v/agents/secrets/%v", org, name)

	req, err := s.client.NewRequest(ctx, "DELETE", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// ListSelectedReposForOrgSecret lists all repositories that have access to an Agents secret.
//
// GitHub API docs: https://docs.github.com/rest/agents/secrets?apiVersion=2026-03-10#list-selected-repositories-for-an-organization-secret
//
//meta:operation GET /orgs/{org}/agents/secrets/{secret_name}/repositories
func (s *AgentsService) ListSelectedReposForOrgSecret(ctx context.Context, org, name string, opts *ListOptions) (*SelectedReposList, *Response, error) {
	u := fmt.Sprintf("orgs/%v/agents/secrets/%v/repositories", org, name)
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

// SetSelectedReposForOrgSecret sets the repositories that have access to an Agents secret.
//
// GitHub API docs: https://docs.github.com/rest/agents/secrets?apiVersion=2026-03-10#set-selected-repositories-for-an-organization-secret
//
//meta:operation PUT /orgs/{org}/agents/secrets/{secret_name}/repositories
func (s *AgentsService) SetSelectedReposForOrgSecret(ctx context.Context, org, name string, ids []int64) (*Response, error) {
	u := fmt.Sprintf("orgs/%v/agents/secrets/%v/repositories", org, name)

	type repoIDs struct {
		SelectedIDs []int64 `json:"selected_repository_ids"`
	}

	req, err := s.client.NewRequest(ctx, "PUT", u, repoIDs{SelectedIDs: ids}, WithVersion(api20260310))
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// AddSelectedRepoToOrgSecret adds a repository to an organization Agents secret.
//
// GitHub API docs: https://docs.github.com/rest/agents/secrets?apiVersion=2026-03-10#add-selected-repository-to-an-organization-secret
//
//meta:operation PUT /orgs/{org}/agents/secrets/{secret_name}/repositories/{repository_id}
func (s *AgentsService) AddSelectedRepoToOrgSecret(ctx context.Context, org, name string, repoID int64) (*Response, error) {
	u := fmt.Sprintf("orgs/%v/agents/secrets/%v/repositories/%v", org, name, repoID)

	req, err := s.client.NewRequest(ctx, "PUT", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// RemoveSelectedRepoFromOrgSecret removes a repository from an organization Agents secret.
//
// GitHub API docs: https://docs.github.com/rest/agents/secrets?apiVersion=2026-03-10#remove-selected-repository-from-an-organization-secret
//
//meta:operation DELETE /orgs/{org}/agents/secrets/{secret_name}/repositories/{repository_id}
func (s *AgentsService) RemoveSelectedRepoFromOrgSecret(ctx context.Context, org, name string, repoID int64) (*Response, error) {
	u := fmt.Sprintf("orgs/%v/agents/secrets/%v/repositories/%v", org, name, repoID)

	req, err := s.client.NewRequest(ctx, "DELETE", u, nil, WithVersion(api20260310))
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}
