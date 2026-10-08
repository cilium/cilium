// Copyright 2026 The go-github AUTHORS. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package github

import (
	"context"
	"fmt"
)

// BudgetScope constants represent the scope of the budget.
const (
	BudgetScopeEnterprise   = "enterprise"
	BudgetScopeOrganization = "organization"
	BudgetScopeRepository   = "repository"
	BudgetScopeCostCenter   = "cost_center"
)

// BudgetType constants represent the type of pricing for the budget.
const (
	BudgetTypeProductPricing = "ProductPricing"
	BudgetTypeSkuPricing     = "SkuPricing"
)

// EnterpriseBudgetAlerting represents alerting settings for a GitHub enterprise budget.
type EnterpriseBudgetAlerting struct {
	WillAlert       *bool    `json:"will_alert,omitempty"`
	AlertRecipients []string `json:"alert_recipients,omitempty"`
}

// EnterpriseBudget represents a GitHub enterprise budget.
type EnterpriseBudget struct {
	ID                  *string                   `json:"id,omitempty"`
	BudgetType          *string                   `json:"budget_type,omitempty"`
	BudgetProductSKU    *string                   `json:"budget_product_sku,omitempty"`
	BudgetScope         *string                   `json:"budget_scope,omitempty"`
	BudgetEntityName    *string                   `json:"budget_entity_name,omitempty"`
	BudgetAmount        *int                      `json:"budget_amount,omitempty"`
	PreventFurtherUsage *bool                     `json:"prevent_further_usage,omitempty"`
	BudgetAlerting      *EnterpriseBudgetAlerting `json:"budget_alerting,omitempty"`
}

func (b EnterpriseBudget) String() string {
	return Stringify(b)
}

// EnterpriseListBudgets represents a collection of GitHub enterprise budgets.
type EnterpriseListBudgets struct {
	Budgets     []*EnterpriseBudget `json:"budgets"`
	HasNextPage *bool               `json:"has_next_page,omitempty"`
	TotalCount  *int                `json:"total_count,omitempty"`
}

// EnterpriseListBudgetsOptions specifies the optional parameters to the
// EnterpriseService.ListBudgets method.
type EnterpriseListBudgetsOptions struct {
	Scope string `url:"scope,omitempty"`
	User  string `url:"user,omitempty"`

	ListOptions
}

// EnterpriseBudgetUserState represents the budget status and consumption of an individual user.
type EnterpriseBudgetUserState struct {
	User             *string `json:"user,omitempty"`
	ConsumedAmount   float64 `json:"consumed_amount"`
	TargetAmount     float64 `json:"target_amount"`
	OverrideBudgetID *string `json:"override_budget_id,omitempty"`
}

func (u EnterpriseBudgetUserState) String() string {
	return Stringify(u)
}

// EnterpriseBudgetUserStates represents the response when retrieving user states for a budget.
type EnterpriseBudgetUserStates struct {
	UserStates  []*EnterpriseBudgetUserState `json:"user_states"`
	HasNextPage bool                         `json:"has_next_page"`
	TotalCount  int                          `json:"total_count"`
}

func (u EnterpriseBudgetUserStates) String() string {
	return Stringify(u)
}

// EnterpriseGetUserStatesOptions specifies the optional parameters to the
// EnterpriseService.GetUserStatesForBudget method.
type EnterpriseGetUserStatesOptions struct {
	SortOrder           int     `url:"sort_order,omitempty"`
	User                string  `url:"user,omitempty"`
	ThresholdLowerBound float64 `url:"threshold_lower_bound,omitempty"`
	ThresholdUpperBound float64 `url:"threshold_upper_bound,omitempty"`

	ListOptions
}

// EnterpriseCreateBudget represents the payload to create a GitHub enterprise budget.
type EnterpriseCreateBudget struct {
	BudgetAmount        int                       `json:"budget_amount"`
	PreventFurtherUsage bool                      `json:"prevent_further_usage"`
	BudgetAlerting      *EnterpriseBudgetAlerting `json:"budget_alerting"`
	BudgetScope         string                    `json:"budget_scope"`
	BudgetEntityName    *string                   `json:"budget_entity_name,omitempty"`
	BudgetType          string                    `json:"budget_type"`
	BudgetProductSKU    *string                   `json:"budget_product_sku,omitempty"`
}

// EnterpriseUpdateBudget represents the payload to update a GitHub enterprise budget.
type EnterpriseUpdateBudget struct {
	BudgetAmount        *int                      `json:"budget_amount,omitempty"`
	PreventFurtherUsage *bool                     `json:"prevent_further_usage,omitempty"`
	BudgetAlerting      *EnterpriseBudgetAlerting `json:"budget_alerting,omitempty"`
	BudgetScope         *string                   `json:"budget_scope,omitempty"`
	BudgetEntityName    *string                   `json:"budget_entity_name,omitempty"`
	BudgetType          *string                   `json:"budget_type,omitempty"`
	BudgetProductSKU    *string                   `json:"budget_product_sku,omitempty"`
}

// EnterpriseCreateOrUpdateBudgetResponse represents the response when creating or updating a budget.
type EnterpriseCreateOrUpdateBudgetResponse struct {
	Message string            `json:"message"`
	Budget  *EnterpriseBudget `json:"budget"`
}

// EnterpriseDeleteBudgetResponse represents the response when deleting a budget.
type EnterpriseDeleteBudgetResponse struct {
	Message string `json:"message"`
	ID      string `json:"id"`
}

// ListBudgets gets all budgets for an enterprise.
//
// GitHub API docs: https://docs.github.com/enterprise-cloud@latest/rest/billing/budgets?apiVersion=2022-11-28#get-all-budgets
//
//meta:operation GET /enterprises/{enterprise}/settings/billing/budgets
func (s *EnterpriseService) ListBudgets(ctx context.Context, enterprise string, opts *EnterpriseListBudgetsOptions) (*EnterpriseListBudgets, *Response, error) {
	u := fmt.Sprintf("enterprises/%v/settings/billing/budgets", enterprise)
	u, err := addOptions(u, opts)
	if err != nil {
		return nil, nil, err
	}

	req, err := s.client.NewRequest(ctx, "GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	var budgets *EnterpriseListBudgets
	resp, err := s.client.Do(req, &budgets)
	if err != nil {
		return nil, resp, err
	}

	return budgets, resp, nil
}

// GetUserStatesForBudget gets user states for a multi-user budget in an enterprise.
//
// GitHub API docs: https://docs.github.com/enterprise-cloud@latest/rest/billing/budgets?apiVersion=2022-11-28#get-user-states-for-a-multi-user-budget
//
//meta:operation GET /enterprises/{enterprise}/settings/billing/budgets/{budget_id}/user-states
func (s *EnterpriseService) GetUserStatesForBudget(ctx context.Context, enterprise, budgetID string, opts *EnterpriseGetUserStatesOptions) (*EnterpriseBudgetUserStates, *Response, error) {
	u := fmt.Sprintf("enterprises/%v/settings/billing/budgets/%v/user-states", enterprise, budgetID)
	u, err := addOptions(u, opts)
	if err != nil {
		return nil, nil, err
	}

	req, err := s.client.NewRequest(ctx, "GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	var userStates *EnterpriseBudgetUserStates
	resp, err := s.client.Do(req, &userStates)
	if err != nil {
		return nil, resp, err
	}

	return userStates, resp, nil
}

// CreateBudget creates a new budget for an enterprise.
//
// GitHub API docs: https://docs.github.com/enterprise-cloud@latest/rest/billing/budgets?apiVersion=2022-11-28#create-a-budget
//
//meta:operation POST /enterprises/{enterprise}/settings/billing/budgets
func (s *EnterpriseService) CreateBudget(ctx context.Context, enterprise string, body EnterpriseCreateBudget) (*EnterpriseCreateOrUpdateBudgetResponse, *Response, error) {
	u := fmt.Sprintf("enterprises/%v/settings/billing/budgets", enterprise)

	req, err := s.client.NewRequest(ctx, "POST", u, body)
	if err != nil {
		return nil, nil, err
	}

	var createBudgetResponse *EnterpriseCreateOrUpdateBudgetResponse
	resp, err := s.client.Do(req, &createBudgetResponse)
	if err != nil {
		return nil, resp, err
	}

	return createBudgetResponse, resp, nil
}

// GetBudget gets a budget by ID for an enterprise.
//
// GitHub API docs: https://docs.github.com/enterprise-cloud@latest/rest/billing/budgets?apiVersion=2022-11-28#get-a-budget-by-id
//
//meta:operation GET /enterprises/{enterprise}/settings/billing/budgets/{budget_id}
func (s *EnterpriseService) GetBudget(ctx context.Context, enterprise, budgetID string) (*EnterpriseBudget, *Response, error) {
	u := fmt.Sprintf("enterprises/%v/settings/billing/budgets/%v", enterprise, budgetID)

	req, err := s.client.NewRequest(ctx, "GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	var budget *EnterpriseBudget
	resp, err := s.client.Do(req, &budget)
	if err != nil {
		return nil, resp, err
	}

	return budget, resp, nil
}

// UpdateBudget updates an existing budget for an enterprise.
//
// GitHub API docs: https://docs.github.com/enterprise-cloud@latest/rest/billing/budgets?apiVersion=2022-11-28#update-a-budget
//
//meta:operation PATCH /enterprises/{enterprise}/settings/billing/budgets/{budget_id}
func (s *EnterpriseService) UpdateBudget(ctx context.Context, enterprise, budgetID string, body EnterpriseUpdateBudget) (*EnterpriseCreateOrUpdateBudgetResponse, *Response, error) {
	u := fmt.Sprintf("enterprises/%v/settings/billing/budgets/%v", enterprise, budgetID)

	req, err := s.client.NewRequest(ctx, "PATCH", u, body)
	if err != nil {
		return nil, nil, err
	}

	var updateBudgetResponse *EnterpriseCreateOrUpdateBudgetResponse
	resp, err := s.client.Do(req, &updateBudgetResponse)
	if err != nil {
		return nil, resp, err
	}

	return updateBudgetResponse, resp, nil
}

// DeleteBudget deletes a budget by ID for an enterprise.
//
// GitHub API docs: https://docs.github.com/enterprise-cloud@latest/rest/billing/budgets?apiVersion=2022-11-28#delete-a-budget
//
//meta:operation DELETE /enterprises/{enterprise}/settings/billing/budgets/{budget_id}
func (s *EnterpriseService) DeleteBudget(ctx context.Context, enterprise, budgetID string) (*EnterpriseDeleteBudgetResponse, *Response, error) {
	u := fmt.Sprintf("enterprises/%v/settings/billing/budgets/%v", enterprise, budgetID)

	req, err := s.client.NewRequest(ctx, "DELETE", u, nil)
	if err != nil {
		return nil, nil, err
	}

	var deleteBudgetResponse *EnterpriseDeleteBudgetResponse
	resp, err := s.client.Do(req, &deleteBudgetResponse)
	if err != nil {
		return nil, resp, err
	}

	return deleteBudgetResponse, resp, nil
}
