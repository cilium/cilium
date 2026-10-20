// Copyright 2013 The go-github AUTHORS. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package github

import (
	"context"
	"fmt"
)

// RepositoryComment represents a comment for a commit, file, or line in a repository.
type RepositoryComment struct {
	HTMLURL           *string    `json:"html_url,omitempty"`
	URL               *string    `json:"url,omitempty"`
	ID                *int64     `json:"id,omitempty"`
	NodeID            *string    `json:"node_id,omitempty"`
	CommitID          *string    `json:"commit_id,omitempty"`
	User              *User      `json:"user,omitempty"`
	AuthorAssociation *string    `json:"author_association,omitempty"`
	Reactions         *Reactions `json:"reactions,omitempty"`
	CreatedAt         *Timestamp `json:"created_at,omitempty"`
	UpdatedAt         *Timestamp `json:"updated_at,omitempty"`
	Body              *string    `json:"body,omitempty"`
	Path              *string    `json:"path,omitempty"`
	Position          *int       `json:"position,omitempty"`
	Line              *int       `json:"line,omitempty"`
}

func (r RepositoryComment) String() string {
	return Stringify(r)
}

// CreateCommitCommentRequest represents a request to create a commit comment.
type CreateCommitCommentRequest struct {
	Body     string  `json:"body"`
	Path     *string `json:"path,omitempty"`
	Position *int    `json:"position,omitempty"`
	// Deprecated: Use Position instead.
	Line *int `json:"line,omitempty"`
}

// UpdateCommitCommentRequest represents a request to update a commit comment.
type UpdateCommitCommentRequest struct {
	Body string `json:"body"`
}

// ListComments lists all the comments for the repository.
//
// GitHub API docs: https://docs.github.com/rest/commits/comments?apiVersion=2022-11-28#list-commit-comments-for-a-repository
//
//meta:operation GET /repos/{owner}/{repo}/comments
func (s *RepositoriesService) ListComments(ctx context.Context, owner, repo string, opts *ListOptions) ([]*RepositoryComment, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/comments", owner, repo)
	u, err := addOptions(u, opts)
	if err != nil {
		return nil, nil, err
	}

	req, err := s.client.NewRequest(ctx, "GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("Accept", mediaTypeReactionsPreview)

	var comments []*RepositoryComment
	resp, err := s.client.Do(req, &comments)
	if err != nil {
		return nil, resp, err
	}

	return comments, resp, nil
}

// ListCommitComments lists all the comments for a given commit SHA.
//
// GitHub API docs: https://docs.github.com/rest/commits/comments?apiVersion=2022-11-28#list-commit-comments
//
//meta:operation GET /repos/{owner}/{repo}/commits/{commit_sha}/comments
func (s *RepositoriesService) ListCommitComments(ctx context.Context, owner, repo, sha string, opts *ListOptions) ([]*RepositoryComment, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/commits/%v/comments", owner, repo, sha)
	u, err := addOptions(u, opts)
	if err != nil {
		return nil, nil, err
	}

	req, err := s.client.NewRequest(ctx, "GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("Accept", mediaTypeReactionsPreview)

	var comments []*RepositoryComment
	resp, err := s.client.Do(req, &comments)
	if err != nil {
		return nil, resp, err
	}

	return comments, resp, nil
}

// CreateComment creates a comment for the given commit.
// Note: GitHub allows for comments to be created for non-existing files and positions.
//
// GitHub API docs: https://docs.github.com/rest/commits/comments?apiVersion=2022-11-28#create-a-commit-comment
//
//meta:operation POST /repos/{owner}/{repo}/commits/{commit_sha}/comments
func (s *RepositoriesService) CreateComment(ctx context.Context, owner, repo, sha string, body CreateCommitCommentRequest) (*RepositoryComment, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/commits/%v/comments", owner, repo, sha)
	req, err := s.client.NewRequest(ctx, "POST", u, body)
	if err != nil {
		return nil, nil, err
	}

	var c *RepositoryComment
	resp, err := s.client.Do(req, &c)
	if err != nil {
		return nil, resp, err
	}

	return c, resp, nil
}

// GetComment gets a single comment from a repository.
//
// GitHub API docs: https://docs.github.com/rest/commits/comments?apiVersion=2022-11-28#get-a-commit-comment
//
//meta:operation GET /repos/{owner}/{repo}/comments/{comment_id}
func (s *RepositoriesService) GetComment(ctx context.Context, owner, repo string, commentID int64) (*RepositoryComment, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/comments/%v", owner, repo, commentID)
	req, err := s.client.NewRequest(ctx, "GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("Accept", mediaTypeReactionsPreview)

	var c *RepositoryComment
	resp, err := s.client.Do(req, &c)
	if err != nil {
		return nil, resp, err
	}

	return c, resp, nil
}

// UpdateComment updates the body of a single comment.
//
// GitHub API docs: https://docs.github.com/rest/commits/comments?apiVersion=2022-11-28#update-a-commit-comment
//
//meta:operation PATCH /repos/{owner}/{repo}/comments/{comment_id}
func (s *RepositoriesService) UpdateComment(ctx context.Context, owner, repo string, commentID int64, body UpdateCommitCommentRequest) (*RepositoryComment, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/comments/%v", owner, repo, commentID)
	req, err := s.client.NewRequest(ctx, "PATCH", u, body)
	if err != nil {
		return nil, nil, err
	}

	var c *RepositoryComment
	resp, err := s.client.Do(req, &c)
	if err != nil {
		return nil, resp, err
	}

	return c, resp, nil
}

// DeleteComment deletes a single comment from a repository.
//
// GitHub API docs: https://docs.github.com/rest/commits/comments?apiVersion=2022-11-28#delete-a-commit-comment
//
//meta:operation DELETE /repos/{owner}/{repo}/comments/{comment_id}
func (s *RepositoriesService) DeleteComment(ctx context.Context, owner, repo string, commentID int64) (*Response, error) {
	u := fmt.Sprintf("repos/%v/%v/comments/%v", owner, repo, commentID)
	req, err := s.client.NewRequest(ctx, "DELETE", u, nil)
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}
