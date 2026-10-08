// Copyright 2026 The go-github AUTHORS. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package github

import (
	"context"
	"fmt"
)

// PullRequestListStacksOptions specifies the optional parameters to the
// PullRequestsService.ListStacks method.
type PullRequestListStacksOptions struct {
	// PullRequest filters stacks to the stack containing this pull request number.
	PullRequest int `url:"pull_request,omitempty"`

	ListOptions
}

// PullRequestCreateStackRequest represents a request to create a pull request stack.
type PullRequestCreateStackRequest struct {
	// PullRequests is an ordered list of pull request numbers from the bottom of the stack to the top.
	PullRequests []int `json:"pull_requests"`
}

// PullRequestAddToStackRequest represents a request to append pull requests to a stack.
type PullRequestAddToStackRequest struct {
	// PullRequests is an ordered list of pull request numbers to append from the current top upward.
	PullRequests []int `json:"pull_requests"`
}

// PullRequestStackRef represents the branch a pull request stack ultimately
// targets. The stacked pull request endpoints return the ref alone, unlike
// PullRequestStackBase, which the pull request endpoints return with a SHA.
type PullRequestStackRef struct {
	// Ref is the name of the branch the entire stack ultimately targets.
	Ref string `json:"ref"`
}

// PullRequestStackDetails represents a pull request stack returned by
// PullRequestsService.CreateStack, GetStack, AddToStack, and Unstack.
type PullRequestStackDetails struct {
	// ID is the ID of the stack.
	ID int64 `json:"id"`
	// Number is the number of the stack.
	Number int `json:"number"`
	// NodeID is the global node ID of the stack.
	NodeID string `json:"node_id"`
	// URL is the API URL of the stack.
	URL string `json:"url"`
	// Base is the branch the entire stack ultimately targets.
	Base *PullRequestStackRef `json:"base"`
	// Open reports whether the stack contains any open pull requests.
	Open bool `json:"open"`
	// CreatedAt is the time the stack was created.
	CreatedAt Timestamp `json:"created_at"`
	// PullRequests contains the pull requests in the stack, from bottom to top.
	PullRequests []*PullRequestStackEntry `json:"pull_requests"`
}

// PullRequestStackEntry represents a pull request in a stack returned by
// PullRequestsService.CreateStack, GetStack, AddToStack, and Unstack.
type PullRequestStackEntry struct {
	// ID is the ID of the pull request.
	ID int64 `json:"id"`
	// Number is the number of the pull request.
	Number int `json:"number"`
	// NodeID is the global node ID of the pull request.
	NodeID string `json:"node_id"`
	// URL is the API URL of the pull request.
	URL string `json:"url"`
	// HTMLURL is the web URL of the pull request.
	HTMLURL string `json:"html_url"`
	// Title is the title of the pull request.
	Title string `json:"title"`
	// State is the state of the pull request. Possible values are: "open" and "closed".
	State string `json:"state"`
	// Draft reports whether the pull request is a draft.
	Draft bool `json:"draft"`
	// MergedAt is the time the pull request was merged, or nil if it is unmerged.
	MergedAt *Timestamp `json:"merged_at"`
	// User is the author of the pull request.
	User *User `json:"user"`
	// Head is the branch the pull request merges from.
	Head *PullRequestStackBranch `json:"head"`
	// Base is the branch the pull request merges into, which is the pull
	// request below it in the stack.
	Base *PullRequestStackBranch `json:"base"`
}

// PullRequestStackBranch represents the head or base branch of a pull request
// returned by the stacked pull request endpoints.
type PullRequestStackBranch struct {
	// Ref is the name of the branch.
	Ref string `json:"ref"`
	// SHA is the SHA of the most recent commit on the branch.
	SHA string `json:"sha"`
	// Repo is the repository the branch belongs to.
	Repo *PullRequestStackRepository `json:"repo"`
}

// PullRequestStackRepository represents the repository a stacked pull
// request's branch belongs to.
type PullRequestStackRepository struct {
	// ID is the ID of the repository.
	ID int64 `json:"id"`
	// URL is the API URL of the repository.
	URL string `json:"url"`
	// Name is the name of the repository.
	Name string `json:"name"`
}

// PullRequestStackMinimal represents a pull request stack returned by
// PullRequestsService.ListStacks. This endpoint returns less detail about each
// pull request in the stack than PullRequestStackDetails carries.
type PullRequestStackMinimal struct {
	// ID is the ID of the stack.
	ID int64 `json:"id"`
	// Number is the number of the stack.
	Number int `json:"number"`
	// NodeID is the global node ID of the stack.
	NodeID string `json:"node_id"`
	// URL is the API URL of the stack.
	URL string `json:"url"`
	// Base is the branch the entire stack ultimately targets.
	Base *PullRequestStackRef `json:"base"`
	// Open reports whether the stack contains any open pull requests.
	Open bool `json:"open"`
	// CreatedAt is the time the stack was created.
	CreatedAt Timestamp `json:"created_at"`
	// PullRequests contains the pull requests in the stack, from bottom to top.
	PullRequests []*PullRequestStackMinimalEntry `json:"pull_requests"`
}

// PullRequestStackMinimalEntry represents a pull request in a stack
// returned by PullRequestsService.ListStacks.
type PullRequestStackMinimalEntry struct {
	// Number is the number of the pull request.
	Number int `json:"number"`
	// State is the state of the pull request. Possible values are: "open" and "closed".
	State string `json:"state"`
	// Draft reports whether the pull request is a draft.
	Draft bool `json:"draft"`
	// MergedAt is the time the pull request was merged, or nil if it is unmerged.
	MergedAt *Timestamp `json:"merged_at"`
	// Head is the branch the pull request merges from.
	Head *PullRequestStackMinimalHead `json:"head"`
}

// PullRequestStackMinimalHead represents the head branch of a pull request
// returned by PullRequestsService.ListStacks.
type PullRequestStackMinimalHead struct {
	// Ref is the name of the branch.
	Ref string `json:"ref"`
	// SHA is the SHA of the most recent commit on the branch.
	SHA string `json:"sha"`
}

// ListStacks lists pull request stacks in a repository.
//
// GitHub API docs: https://docs.github.com/rest/pulls/stacks?apiVersion=2022-11-28#list-pull-request-stacks
//
//meta:operation GET /repos/{owner}/{repo}/stacks
func (s *PullRequestsService) ListStacks(ctx context.Context, owner, repo string, opts *PullRequestListStacksOptions) ([]*PullRequestStackMinimal, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/stacks", owner, repo)
	u, err := addOptions(u, opts)
	if err != nil {
		return nil, nil, err
	}

	req, err := s.client.NewRequest(ctx, "GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	var stacks []*PullRequestStackMinimal
	resp, err := s.client.Do(req, &stacks)
	if err != nil {
		return nil, resp, err
	}

	return stacks, resp, nil
}

// CreateStack creates a pull request stack from an ordered list of pull request numbers.
//
// GitHub API docs: https://docs.github.com/rest/pulls/stacks?apiVersion=2022-11-28#create-a-pull-request-stack
//
//meta:operation POST /repos/{owner}/{repo}/stacks
func (s *PullRequestsService) CreateStack(ctx context.Context, owner, repo string, body PullRequestCreateStackRequest) (*PullRequestStackDetails, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/stacks", owner, repo)
	req, err := s.client.NewRequest(ctx, "POST", u, body)
	if err != nil {
		return nil, nil, err
	}

	var stack *PullRequestStackDetails
	resp, err := s.client.Do(req, &stack)
	if err != nil {
		return nil, resp, err
	}

	return stack, resp, nil
}

// GetStack gets a pull request stack by its stack number.
//
// GitHub API docs: https://docs.github.com/rest/pulls/stacks?apiVersion=2022-11-28#get-a-pull-request-stack
//
//meta:operation GET /repos/{owner}/{repo}/stacks/{stack_number}
func (s *PullRequestsService) GetStack(ctx context.Context, owner, repo string, stackNumber int) (*PullRequestStackDetails, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/stacks/%v", owner, repo, stackNumber)
	req, err := s.client.NewRequest(ctx, "GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	var stack *PullRequestStackDetails
	resp, err := s.client.Do(req, &stack)
	if err != nil {
		return nil, resp, err
	}

	return stack, resp, nil
}

// AddToStack appends pull requests to a pull request stack.
//
// GitHub API docs: https://docs.github.com/rest/pulls/stacks?apiVersion=2022-11-28#add-pull-requests-to-a-pull-request-stack
//
//meta:operation POST /repos/{owner}/{repo}/stacks/{stack_number}/add
func (s *PullRequestsService) AddToStack(ctx context.Context, owner, repo string, stackNumber int, body PullRequestAddToStackRequest) (*PullRequestStackDetails, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/stacks/%v/add", owner, repo, stackNumber)
	req, err := s.client.NewRequest(ctx, "POST", u, body)
	if err != nil {
		return nil, nil, err
	}

	var stack *PullRequestStackDetails
	resp, err := s.client.Do(req, &stack)
	if err != nil {
		return nil, resp, err
	}

	return stack, resp, nil
}

// Unstack removes the unmerged pull requests from a pull request stack. It
// returns nil when no pull requests remain and the stack is dissolved.
//
// GitHub API docs: https://docs.github.com/rest/pulls/stacks?apiVersion=2022-11-28#remove-pull-requests-from-a-pull-request-stack
//
//meta:operation POST /repos/{owner}/{repo}/stacks/{stack_number}/unstack
func (s *PullRequestsService) Unstack(ctx context.Context, owner, repo string, stackNumber int) (*PullRequestStackDetails, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/stacks/%v/unstack", owner, repo, stackNumber)
	req, err := s.client.NewRequest(ctx, "POST", u, nil)
	if err != nil {
		return nil, nil, err
	}

	var stack *PullRequestStackDetails
	resp, err := s.client.Do(req, &stack)
	if err != nil {
		return nil, resp, err
	}

	return stack, resp, nil
}
