// Copyright 2014 The go-github AUTHORS. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package github

import (
	"context"
	"fmt"
)

// PromoteSiteAdmin promotes a user to a site administrator of a GitHub Enterprise instance.
//
// GitHub API docs: https://docs.github.com/enterprise-server@3.22/rest/enterprise-admin/users#promote-a-user-to-be-a-site-administrator
//
//meta:operation PUT /users/{username}/site_admin
func (s *UsersService) PromoteSiteAdmin(ctx context.Context, user string) (*Response, error) {
	u := fmt.Sprintf("users/%v/site_admin", user)

	req, err := s.client.NewRequest(ctx, "PUT", u, nil)
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// DemoteSiteAdmin demotes a user from site administrator of a GitHub Enterprise instance.
//
// GitHub API docs: https://docs.github.com/enterprise-server@3.22/rest/enterprise-admin/users#demote-a-site-administrator
//
//meta:operation DELETE /users/{username}/site_admin
func (s *UsersService) DemoteSiteAdmin(ctx context.Context, user string) (*Response, error) {
	u := fmt.Sprintf("users/%v/site_admin", user)

	req, err := s.client.NewRequest(ctx, "DELETE", u, nil)
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// SuspendUserRequest represents a request to suspend a user.
type SuspendUserRequest struct {
	Reason *string `json:"reason,omitempty"`
}

// Suspend a user on a GitHub Enterprise instance.
//
// GitHub API docs: https://docs.github.com/enterprise-server@3.22/rest/enterprise-admin/users#suspend-a-user
//
//meta:operation PUT /users/{username}/suspended
func (s *UsersService) Suspend(ctx context.Context, user string, body SuspendUserRequest) (*Response, error) {
	u := fmt.Sprintf("users/%v/suspended", user)

	req, err := s.client.NewRequest(ctx, "PUT", u, body)
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// UnsuspendUserRequest represents a request to unsuspend a user.
type UnsuspendUserRequest struct {
	// Reason is the reason the user is being unsuspended, which is logged in the audit log.
	// If it is not provided, it defaults to "Unsuspended via API by SITE_ADMINISTRATOR",
	// where SITE_ADMINISTRATOR is the person who performed the action.
	Reason *string `json:"reason,omitempty"`
}

// Unsuspend a user on a GitHub Enterprise instance.
//
// GitHub API docs: https://docs.github.com/enterprise-server@3.22/rest/enterprise-admin/users#unsuspend-a-user
//
//meta:operation DELETE /users/{username}/suspended
func (s *UsersService) Unsuspend(ctx context.Context, user string, body UnsuspendUserRequest) (*Response, error) {
	u := fmt.Sprintf("users/%v/suspended", user)

	req, err := s.client.NewRequest(ctx, "DELETE", u, body)
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}
