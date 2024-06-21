// Copyright 2023 The go-github AUTHORS. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package github

import (
	"context"
	"encoding/json"
	"fmt"
)

// BypassActor represents the bypass actors from a ruleset.
type BypassActor struct {
	ActorID *int64 `json:"actor_id,omitempty"`
	// Possible values for ActorType are: RepositoryRole, Team, Integration, OrganizationAdmin
	ActorType *string `json:"actor_type,omitempty"`
	// Possible values for BypassMode are: always, pull_request
	BypassMode *string `json:"bypass_mode,omitempty"`
}

// RulesetLink represents a single link object from GitHub ruleset request _links.
type RulesetLink struct {
	HRef *string `json:"href,omitempty"`
}

// RulesetLinks represents the "_links" object in a Ruleset.
type RulesetLinks struct {
	Self *RulesetLink `json:"self,omitempty"`
}

// RulesetRefConditionParameters represents the conditions object for ref_names.
type RulesetRefConditionParameters struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

// RulesetRepositoryNamesConditionParameters represents the conditions object for repository_names.
type RulesetRepositoryNamesConditionParameters struct {
	Include   []string `json:"include"`
	Exclude   []string `json:"exclude"`
	Protected *bool    `json:"protected,omitempty"`
}

// RulesetRepositoryIDsConditionParameters represents the conditions object for repository_ids.
type RulesetRepositoryIDsConditionParameters struct {
	RepositoryIDs []int64 `json:"repository_ids,omitempty"`
}

// RulesetRepositoryPropertyTargetParameters represents a repository_property name and values to be used for targeting.
type RulesetRepositoryPropertyTargetParameters struct {
	Name   string   `json:"name"`
	Values []string `json:"property_values"`
	Source *string  `json:"source,omitempty"`
}

// RulesetRepositoryPropertyConditionParameters represents the conditions object for repository_property.
type RulesetRepositoryPropertyConditionParameters struct {
	Include []RulesetRepositoryPropertyTargetParameters `json:"include"`
	Exclude []RulesetRepositoryPropertyTargetParameters `json:"exclude"`
}

// RulesetConditions represents the conditions object in a ruleset.
// Set either RepositoryName or RepositoryID or RepositoryProperty, not more than one.
type RulesetConditions struct {
	RefName            *RulesetRefConditionParameters                `json:"ref_name,omitempty"`
	RepositoryName     *RulesetRepositoryNamesConditionParameters    `json:"repository_name,omitempty"`
	RepositoryID       *RulesetRepositoryIDsConditionParameters      `json:"repository_id,omitempty"`
	RepositoryProperty *RulesetRepositoryPropertyConditionParameters `json:"repository_property,omitempty"`
}

// RulePatternParameters represents the rule pattern parameters.
type RulePatternParameters struct {
	Name *string `json:"name,omitempty"`
	// If Negate is true, the rule will fail if the pattern matches.
	Negate *bool `json:"negate,omitempty"`
	// Possible values for Operator are: starts_with, ends_with, contains, regex
	Operator string `json:"operator"`
	Pattern  string `json:"pattern"`
}

// RuleFileParameters represents a list of file paths.
type RuleFileParameters struct {
	RestrictedFilePaths *[]string `json:"restricted_file_paths"`
}

// RuleMaxFilePathLengthParameters represents the max_file_path_length rule parameters.
type RuleMaxFilePathLengthParameters struct {
	MaxFilePathLength int `json:"max_file_path_length"`
}

// RuleFileExtensionRestrictionParameters represents the file_extension_restriction rule parameters.
type RuleFileExtensionRestrictionParameters struct {
	RestrictedFileExtensions []string `json:"restricted_file_extensions"`
}

// RuleMaxFileSizeParameters represents the max_file_size rule parameters.
type RuleMaxFileSizeParameters struct {
	MaxFileSize int64 `json:"max_file_size"`
}

// UpdateAllowsFetchAndMergeRuleParameters represents the update rule parameters.
type UpdateAllowsFetchAndMergeRuleParameters struct {
	UpdateAllowsFetchAndMerge bool `json:"update_allows_fetch_and_merge"`
}

// RequiredDeploymentEnvironmentsRuleParameters represents the required_deployments rule parameters.
type RequiredDeploymentEnvironmentsRuleParameters struct {
	RequiredDeploymentEnvironments []string `json:"required_deployment_environments"`
}

// PullRequestRuleParameters represents the pull_request rule parameters.
type PullRequestRuleParameters struct {
	DismissStaleReviewsOnPush      bool `json:"dismiss_stale_reviews_on_push"`
	RequireCodeOwnerReview         bool `json:"require_code_owner_review"`
	RequireLastPushApproval        bool `json:"require_last_push_approval"`
	RequiredApprovingReviewCount   int  `json:"required_approving_review_count"`
	RequiredReviewThreadResolution bool `json:"required_review_thread_resolution"`
}

// RuleRequiredStatusChecks represents the RequiredStatusChecks for the RequiredStatusChecksRuleParameters object.
type RuleRequiredStatusChecks struct {
	Context       string `json:"context"`
	IntegrationID *int64 `json:"integration_id,omitempty"`
}

// MergeQueueRuleParameters represents the merge_queue rule parameters.
type MergeQueueRuleParameters struct {
	CheckResponseTimeoutMinutes int `json:"check_response_timeout_minutes"`
	// Possible values for GroupingStrategy are: ALLGREEN, HEADGREEN
	GroupingStrategy  string `json:"grouping_strategy"`
	MaxEntriesToBuild int    `json:"max_entries_to_build"`
	MaxEntriesToMerge int    `json:"max_entries_to_merge"`
	// Possible values for MergeMethod are: MERGE, SQUASH, REBASE
	MergeMethod                  string `json:"merge_method"`
	MinEntriesToMerge            int    `json:"min_entries_to_merge"`
	MinEntriesToMergeWaitMinutes int    `json:"min_entries_to_merge_wait_minutes"`
}

// RequiredStatusChecksRuleParameters represents the required_status_checks rule parameters.
type RequiredStatusChecksRuleParameters struct {
	DoNotEnforceOnCreate             *bool                      `json:"do_not_enforce_on_create,omitempty"`
	RequiredStatusChecks             []RuleRequiredStatusChecks `json:"required_status_checks"`
	StrictRequiredStatusChecksPolicy bool                       `json:"strict_required_status_checks_policy"`
}

// RuleRequiredWorkflow represents the Workflow for the RequireWorkflowsRuleParameters object.
type RuleRequiredWorkflow struct {
	Path         string  `json:"path"`
	Ref          *string `json:"ref,omitempty"`
	RepositoryID *int64  `json:"repository_id,omitempty"`
	Sha          *string `json:"sha,omitempty"`
}

// RequiredWorkflowsRuleParameters represents the workflows rule parameters.
type RequiredWorkflowsRuleParameters struct {
	DoNotEnforceOnCreate bool                    `json:"do_not_enforce_on_create,omitempty"`
	RequiredWorkflows    []*RuleRequiredWorkflow `json:"workflows"`
}

// RuleRequiredCodeScanningTool represents a single required code-scanning tool for the RequiredCodeScanningParameters object.
type RuleRequiredCodeScanningTool struct {
	AlertsThreshold         string `json:"alerts_threshold"`
	SecurityAlertsThreshold string `json:"security_alerts_threshold"`
	Tool                    string `json:"tool"`
}

// RequiredCodeScanningRuleParameters represents the code_scanning rule parameters.
type RequiredCodeScanningRuleParameters struct {
	RequiredCodeScanningTools []*RuleRequiredCodeScanningTool `json:"code_scanning_tools"`
}

// RepositoryRule represents a GitHub Rule.
type RepositoryRule struct {
	Type              string           `json:"type"`
	Parameters        *json.RawMessage `json:"parameters,omitempty"`
	RulesetSourceType string           `json:"ruleset_source_type"`
	RulesetSource     string           `json:"ruleset_source"`
	RulesetID         int64            `json:"ruleset_id"`
}

// RepositoryRulesetEditedChanges represents  the changes made to a repository ruleset.
type RepositoryRulesetEditedChanges struct {
	Name        *RepositoryRulesetEditedSource     `json:"name,omitempty"`
	Enforcement *RepositoryRulesetEditedSource     `json:"enforcement,omitempty"`
	Conditions  *RepositoryRulesetEditedConditions `json:"conditions,omitempty"`
	Rules       *RepositoryRulesetEditedRules      `json:"rules,omitempty"`
}

// RepositoryRulesetEditedSource represents a source change for the ruleset.
type RepositoryRulesetEditedSource struct {
	From *string `json:"from,omitempty"`
}

// RepositoryRulesetEditedSources represents multiple source changes for the ruleset.
type RepositoryRulesetEditedSources struct {
	From []string `json:"from,omitempty"`
}

// RepositoryRulesetEditedConditions holds changes to conditions in a ruleset.
type RepositoryRulesetEditedConditions struct {
	Added   []*RepositoryRulesetRefCondition            `json:"added,omitempty"`
	Deleted []*RepositoryRulesetRefCondition            `json:"deleted,omitempty"`
	Updated []*RepositoryRulesetEditedUpdatedConditions `json:"updated,omitempty"`
}

// RepositoryRulesetEditedRules holds changes to rules in a ruleset.
type RepositoryRulesetEditedRules struct {
	Added   []*RepositoryRulesetRule         `json:"added,omitempty"`
	Deleted []*RepositoryRulesetRule         `json:"deleted,omitempty"`
	Updated []*RepositoryRulesetUpdatedRules `json:"updated,omitempty"`
}

// RepositoryRulesetRefCondition represents a reference condition for the ruleset.
type RepositoryRulesetRefCondition struct {
	RefName *RulesetRefConditionParameters `json:"ref_name,omitempty"`
}

// RepositoryRulesetEditedUpdatedConditions holds updates to conditions in a ruleset.
type RepositoryRulesetEditedUpdatedConditions struct {
	Condition *RepositoryRulesetRefCondition            `json:"condition,omitempty"`
	Changes   *RepositoryRulesetUpdatedConditionsEdited `json:"changes,omitempty"`
}

// RepositoryRulesetUpdatedConditionsEdited holds the edited updates to conditions in a ruleset.
type RepositoryRulesetUpdatedConditionsEdited struct {
	ConditionType *RepositoryRulesetEditedSource  `json:"condition_type,omitempty"`
	Target        *RepositoryRulesetEditedSource  `json:"target,omitempty"`
	Include       *RepositoryRulesetEditedSources `json:"include,omitempty"`
	Exclude       *RepositoryRulesetEditedSources `json:"exclude,omitempty"`
}

// RepositoryRulesetUpdatedRules holds updates to rules in a ruleset.
type RepositoryRulesetUpdatedRules struct {
	Rule    *RepositoryRulesetRule              `json:"rule,omitempty"`
	Changes *RepositoryRulesetEditedRuleChanges `json:"changes,omitempty"`
}

// RepositoryRulesetEditedRuleChanges holds changes made to a rule in a ruleset.
type RepositoryRulesetEditedRuleChanges struct {
	Configuration *RepositoryRulesetEditedSources `json:"configuration,omitempty"`
	RuleType      *RepositoryRulesetEditedSources `json:"rule_type,omitempty"`
	Pattern       *RepositoryRulesetEditedSources `json:"pattern,omitempty"`
}

// RepositoryRuleset represents the structure of a ruleset associated with a GitHub repository.
type RepositoryRuleset struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	// Possible values for target: "branch", "tag", "push"
	Target *string `json:"target,omitempty"`
	// Possible values for source type: "Repository", "Organization"
	SourceType *string `json:"source_type,omitempty"`
	Source     string  `json:"source"`
	// Possible values for enforcement: "disabled", "active", "evaluate"
	Enforcement  string         `json:"enforcement"`
	BypassActors []*BypassActor `json:"bypass_actors,omitempty"`
	// Possible values for current user can bypass: "always", "pull_requests_only", "never"
	CurrentUserCanBypass *string                  `json:"current_user_can_bypass,omitempty"`
	NodeID               *string                  `json:"node_id,omitempty"`
	Links                *RepositoryRulesetLink   `json:"_links,omitempty"`
	Conditions           json.RawMessage          `json:"conditions,omitempty"`
	Rules                []*RepositoryRulesetRule `json:"rules,omitempty"`
	CreatedAt            *Timestamp               `json:"created_at,omitempty"`
	UpdatedAt            *Timestamp               `json:"updated_at,omitempty"`
}

// RepositoryRulesetRule represents individual rules which are present in a repository's ruleset.
type RepositoryRulesetRule struct {
	Creation                 *RepositoryRulesetRuleType                     `json:"creation,omitempty"`
	Update                   *RepositoryRulesetUpdateRule                   `json:"update,omitempty"`
	Deletion                 *RepositoryRulesetRuleType                     `json:"deletion,omitempty"`
	RequiredLinearHistory    *RepositoryRulesetRuleType                     `json:"required_linear_history,omitempty"`
	MergeQueue               *RepositoryRulesetMergeQueueRule               `json:"merge_queue,omitempty"`
	RequiredDeployments      *RepositoryRulesetRequiredDeploymentsRule      `json:"required_deployments,omitempty"`
	RequiredSignatures       *RepositoryRulesetRuleType                     `json:"required_signatures,omitempty"`
	PullRequest              *RepositoryRulesetPullRequestRule              `json:"pull_request,omitempty"`
	RequiredStatusChecks     *RepositoryRulesetRequiredStatusChecksRule     `json:"required_status_checks,omitempty"`
	NonFastForward           *RepositoryRulesetRuleType                     `json:"non_fast_forward,omitempty"`
	CommitMessagePattern     *RepositoryRulesetPatternRule                  `json:"commit_message_pattern,omitempty"`
	CommitAuthorEmailPattern *RepositoryRulesetPatternRule                  `json:"commit_author_email_pattern,omitempty"`
	CommitterEmailPattern    *RepositoryRulesetPatternRule                  `json:"committer_email_pattern,omitempty"`
	BranchNamePattern        *RepositoryRulesetPatternRule                  `json:"branch_name_pattern,omitempty"`
	TagNamePattern           *RepositoryRulesetPatternRule                  `json:"tag_name_pattern,omitempty"`
	FilePathRestriction      *RepositoryRulesetFilePathRestrictionRule      `json:"file_path_restriction,omitempty"`
	MaxFilePathLength        *RepositoryRulesetMaxFilePathLengthRule        `json:"max_file_path_length,omitempty"`
	FileExtensionRestriction *RepositoryRulesetFileExtensionRestrictionRule `json:"file_extension_restriction,omitempty"`
	MaxFileSize              *RepositoryRulesetMaxFileSizeRule              `json:"max_file_size,omitempty"`
	Workflows                *RepositoryRulesetWorkflowsRule                `json:"workflows,omitempty"`
	CodeScanning             *RepositoryRulesetCodeScanningRule             `json:"code_scanning,omitempty"`
}

// RepositoryRulesetLink represents Links associated with a repository's rulesets. These links are used to provide more information about the ruleset.
type RepositoryRulesetLink struct {
	Self *RulesetLink `json:"self,omitempty"`
	HTML *RulesetLink `json:"html,omitempty"`
}

// RepositoryRulesetRuleType represents the type of a ruleset rule.
type RepositoryRulesetRuleType struct {
	Type string `json:"type"`
}

// RepositoryRulesetUpdateRule defines an update rule for the repository.
type RepositoryRulesetUpdateRule struct {
	// Type can be one of: "update".
	Type       string                                   `json:"type"`
	Parameters *UpdateAllowsFetchAndMergeRuleParameters `json:"parameters,omitempty"`
}

// RepositoryRulesetMergeQueueRule defines a merge queue rule for the repository.
type RepositoryRulesetMergeQueueRule struct {
	// Type can be one of: "merge_queue".
	Type       string                    `json:"type"`
	Parameters *MergeQueueRuleParameters `json:"parameters,omitempty"`
}

// RepositoryRulesetRequiredDeploymentsRule defines a rule for required deployments.
type RepositoryRulesetRequiredDeploymentsRule struct {
	// Type can be one of: "required_deployments".
	Type       string                                        `json:"type"`
	Parameters *RequiredDeploymentEnvironmentsRuleParameters `json:"parameters,omitempty"`
}

// RepositoryRulesetPullRequestRule defines a rule for pull requests.
type RepositoryRulesetPullRequestRule struct {
	// Type can be one of: "pull_request".

	Type       string                     `json:"type"`
	Parameters *PullRequestRuleParameters `json:"parameters,omitempty"`
}

// RepositoryRulesetRequiredStatusChecksRule defines a rule for required status checks.
type RepositoryRulesetRequiredStatusChecksRule struct {
	// Type can be one of: "required_status_checks".

	Type       string                              `json:"type"`
	Parameters *RequiredStatusChecksRuleParameters `json:"parameters,omitempty"`
}

// RepositoryRulesetPatternRule defines a pattern rule for the repository.
type RepositoryRulesetPatternRule struct {
	Type       string                 `json:"type"`
	Parameters *RulePatternParameters `json:"parameters,omitempty"`
}

// RepositoryRulesetFilePathRestrictionRule defines a file path restriction rule for the repository.
type RepositoryRulesetFilePathRestrictionRule struct {
	// Type can be one of: "file_path_restriction".
	Type       string              `json:"type"`
	Parameters *RuleFileParameters `json:"parameters,omitempty"`
}

// RepositoryRulesetMaxFilePathLengthRule defines a maximum file path length rule for the repository.
type RepositoryRulesetMaxFilePathLengthRule struct {
	// Type can be one of: "max_file_path_length".

	Type       string                           `json:"type"`
	Parameters *RuleMaxFilePathLengthParameters `json:"parameters,omitempty"`
}

// RepositoryRulesetFileExtensionRestrictionRule defines a file extension restriction rule for the repository.
type RepositoryRulesetFileExtensionRestrictionRule struct {
	// Type can be one of: "file_extension_restriction".
	Type       string                                  `json:"type"`
	Parameters *RuleFileExtensionRestrictionParameters `json:"parameters,omitempty"`
}

// RepositoryRulesetMaxFileSizeRule defines a maximum file size rule for the repository.
type RepositoryRulesetMaxFileSizeRule struct {
	// Type can be one of: "max_file_size".
	Type       string                     `json:"type"`
	Parameters *RuleMaxFileSizeParameters `json:"parameters,omitempty"`
}

// RepositoryRulesetWorkflowsRule defines a workflow rule for the repository.
type RepositoryRulesetWorkflowsRule struct {
	// Type can be one of: "workflows".
	Type       string                           `json:"type"`
	Parameters *RequiredWorkflowsRuleParameters `json:"parameters,omitempty"`
}

// RepositoryRulesetCodeScanningRule defines a code scanning rule for the repository.
type RepositoryRulesetCodeScanningRule struct {
	// Type can be one of: "code_scanning".
	Type       string                      `json:"type"`
	Parameters *RuleCodeScanningParameters `json:"parameters,omitempty"`
}

// RuleCodeScanningParameters defines parameters for code scanning rules.
type RuleCodeScanningParameters struct {
	CodeScanningTools []*CodeScanningTool `json:"code_scanning_tools,omitempty"`
}

// CodeScanningTool defines a specific tool used for code scanning.
type CodeScanningTool struct {
	AlertsThreshold         string `json:"alerts_threshold"`
	SecurityAlertsThreshold string `json:"security_alerts_threshold"`
	Tool                    string `json:"tool"`
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// This helps us handle the fact that RepositoryRule parameter field can be of numerous types.
func (r *RepositoryRule) UnmarshalJSON(data []byte) error {
	type rule RepositoryRule
	var repositoryRule rule
	if err := json.Unmarshal(data, &repositoryRule); err != nil {
		return err
	}

	r.RulesetID = repositoryRule.RulesetID
	r.RulesetSourceType = repositoryRule.RulesetSourceType
	r.RulesetSource = repositoryRule.RulesetSource
	r.Type = repositoryRule.Type

	switch repositoryRule.Type {
	case "creation", "deletion", "non_fast_forward", "required_linear_history", "required_signatures":
		r.Parameters = nil
	case "update":
		if repositoryRule.Parameters == nil {
			r.Parameters = nil
			return nil
		}
		params := UpdateAllowsFetchAndMergeRuleParameters{}
		if err := json.Unmarshal(*repositoryRule.Parameters, &params); err != nil {
			return err
		}

		bytes, _ := json.Marshal(params)
		rawParams := json.RawMessage(bytes)

		r.Parameters = &rawParams
	case "merge_queue":
		if repositoryRule.Parameters == nil {
			r.Parameters = nil
			return nil
		}
		params := MergeQueueRuleParameters{}
		if err := json.Unmarshal(*repositoryRule.Parameters, &params); err != nil {
			return err
		}

		bytes, _ := json.Marshal(params)
		rawParams := json.RawMessage(bytes)

		r.Parameters = &rawParams
	case "required_deployments":
		params := RequiredDeploymentEnvironmentsRuleParameters{}
		if err := json.Unmarshal(*repositoryRule.Parameters, &params); err != nil {
			return err
		}

		bytes, _ := json.Marshal(params)
		rawParams := json.RawMessage(bytes)

		r.Parameters = &rawParams
	case "commit_message_pattern", "commit_author_email_pattern", "committer_email_pattern", "branch_name_pattern", "tag_name_pattern":
		params := RulePatternParameters{}
		if err := json.Unmarshal(*repositoryRule.Parameters, &params); err != nil {
			return err
		}

		bytes, _ := json.Marshal(params)
		rawParams := json.RawMessage(bytes)

		r.Parameters = &rawParams
	case "pull_request":
		params := PullRequestRuleParameters{}
		if err := json.Unmarshal(*repositoryRule.Parameters, &params); err != nil {
			return err
		}

		bytes, _ := json.Marshal(params)
		rawParams := json.RawMessage(bytes)

		r.Parameters = &rawParams
	case "required_status_checks":
		params := RequiredStatusChecksRuleParameters{}
		if err := json.Unmarshal(*repositoryRule.Parameters, &params); err != nil {
			return err
		}

		bytes, _ := json.Marshal(params)
		rawParams := json.RawMessage(bytes)

		r.Parameters = &rawParams
	case "workflows":
		params := RequiredWorkflowsRuleParameters{}
		if err := json.Unmarshal(*repositoryRule.Parameters, &params); err != nil {
			return err
		}

		bytes, _ := json.Marshal(params)
		rawParams := json.RawMessage(bytes)

		r.Parameters = &rawParams
	case "file_path_restriction":
		params := RuleFileParameters{}
		if err := json.Unmarshal(*repositoryRule.Parameters, &params); err != nil {
			return err
		}
		bytes, _ := json.Marshal(params)
		rawParams := json.RawMessage(bytes)

		r.Parameters = &rawParams
	case "code_scanning":
		params := RequiredCodeScanningRuleParameters{}
		if err := json.Unmarshal(*repositoryRule.Parameters, &params); err != nil {
			return err
		}
		bytes, _ := json.Marshal(params)
		rawParams := json.RawMessage(bytes)

		r.Parameters = &rawParams
	case "max_file_path_length":
		params := RuleMaxFilePathLengthParameters{}
		if err := json.Unmarshal(*repositoryRule.Parameters, &params); err != nil {
			return err
		}
		bytes, _ := json.Marshal(params)
		rawParams := json.RawMessage(bytes)

		r.Parameters = &rawParams
	case "file_extension_restriction":
		params := RuleFileExtensionRestrictionParameters{}
		if err := json.Unmarshal(*repositoryRule.Parameters, &params); err != nil {
			return err
		}
		bytes, _ := json.Marshal(params)
		rawParams := json.RawMessage(bytes)

		r.Parameters = &rawParams
	case "max_file_size":
		params := RuleMaxFileSizeParameters{}
		if err := json.Unmarshal(*repositoryRule.Parameters, &params); err != nil {
			return err
		}
		bytes, _ := json.Marshal(params)
		rawParams := json.RawMessage(bytes)

		r.Parameters = &rawParams
	default:
		r.Type = ""
		r.Parameters = nil
		return fmt.Errorf("RepositoryRule.Type %q is not yet implemented, unable to unmarshal (%#v)", repositoryRule.Type, repositoryRule)
	}

	return nil
}

// NewMergeQueueRule creates a rule to only allow merges via a merge queue.
func NewMergeQueueRule(params *MergeQueueRuleParameters) (rule *RepositoryRule) {
	if params != nil {
		bytes, _ := json.Marshal(params)

		rawParams := json.RawMessage(bytes)

		return &RepositoryRule{
			Type:       "merge_queue",
			Parameters: &rawParams,
		}
	}
	return &RepositoryRule{
		Type: "merge_queue",
	}
}

// NewCreationRule creates a rule to only allow users with bypass permission to create matching refs.
func NewCreationRule() (rule *RepositoryRule) {
	return &RepositoryRule{
		Type: "creation",
	}
}

// NewUpdateRule creates a rule to only allow users with bypass permission to update matching refs.
func NewUpdateRule(params *UpdateAllowsFetchAndMergeRuleParameters) (rule *RepositoryRule) {
	if params != nil {
		bytes, _ := json.Marshal(params)

		rawParams := json.RawMessage(bytes)

		return &RepositoryRule{
			Type:       "update",
			Parameters: &rawParams,
		}
	}
	return &RepositoryRule{
		Type: "update",
	}
}

// NewDeletionRule creates a rule to only allow users with bypass permissions to delete matching refs.
func NewDeletionRule() (rule *RepositoryRule) {
	return &RepositoryRule{
		Type: "deletion",
	}
}

// NewRequiredLinearHistoryRule creates a rule to prevent merge commits from being pushed to matching branches.
func NewRequiredLinearHistoryRule() (rule *RepositoryRule) {
	return &RepositoryRule{
		Type: "required_linear_history",
	}
}

// NewRequiredDeploymentsRule creates a rule to require environments to be successfully deployed before they can be merged into the matching branches.
func NewRequiredDeploymentsRule(params *RequiredDeploymentEnvironmentsRuleParameters) (rule *RepositoryRule) {
	bytes, _ := json.Marshal(params)

	rawParams := json.RawMessage(bytes)

	return &RepositoryRule{
		Type:       "required_deployments",
		Parameters: &rawParams,
	}
}

// NewRequiredSignaturesRule creates a rule a to require commits pushed to matching branches to have verified signatures.
func NewRequiredSignaturesRule() (rule *RepositoryRule) {
	return &RepositoryRule{
		Type: "required_signatures",
	}
}

// NewPullRequestRule creates a rule to require all commits be made to a non-target branch and submitted via a pull request before they can be merged.
func NewPullRequestRule(params *PullRequestRuleParameters) (rule *RepositoryRule) {
	bytes, _ := json.Marshal(params)

	rawParams := json.RawMessage(bytes)

	return &RepositoryRule{
		Type:       "pull_request",
		Parameters: &rawParams,
	}
}

// NewRequiredStatusChecksRule creates a rule to require which status checks must pass before branches can be merged into a branch rule.
func NewRequiredStatusChecksRule(params *RequiredStatusChecksRuleParameters) (rule *RepositoryRule) {
	bytes, _ := json.Marshal(params)

	rawParams := json.RawMessage(bytes)

	return &RepositoryRule{
		Type:       "required_status_checks",
		Parameters: &rawParams,
	}
}

// NewNonFastForwardRule creates a rule as part to prevent users with push access from force pushing to matching branches.
func NewNonFastForwardRule() (rule *RepositoryRule) {
	return &RepositoryRule{
		Type: "non_fast_forward",
	}
}

// NewCommitMessagePatternRule creates a rule to restrict commit message patterns being pushed to matching branches.
func NewCommitMessagePatternRule(params *RulePatternParameters) (rule *RepositoryRule) {
	bytes, _ := json.Marshal(params)

	rawParams := json.RawMessage(bytes)

	return &RepositoryRule{
		Type:       "commit_message_pattern",
		Parameters: &rawParams,
	}
}

// NewCommitAuthorEmailPatternRule creates a rule to restrict commits with author email patterns being merged into matching branches.
func NewCommitAuthorEmailPatternRule(params *RulePatternParameters) (rule *RepositoryRule) {
	bytes, _ := json.Marshal(params)

	rawParams := json.RawMessage(bytes)

	return &RepositoryRule{
		Type:       "commit_author_email_pattern",
		Parameters: &rawParams,
	}
}

// NewCommitterEmailPatternRule creates a rule to restrict commits with committer email patterns being merged into matching branches.
func NewCommitterEmailPatternRule(params *RulePatternParameters) (rule *RepositoryRule) {
	bytes, _ := json.Marshal(params)

	rawParams := json.RawMessage(bytes)

	return &RepositoryRule{
		Type:       "committer_email_pattern",
		Parameters: &rawParams,
	}
}

// NewBranchNamePatternRule creates a rule to restrict branch patterns from being merged into matching branches.
func NewBranchNamePatternRule(params *RulePatternParameters) (rule *RepositoryRule) {
	bytes, _ := json.Marshal(params)

	rawParams := json.RawMessage(bytes)

	return &RepositoryRule{
		Type:       "branch_name_pattern",
		Parameters: &rawParams,
	}
}

// NewTagNamePatternRule creates a rule to restrict tag patterns contained in non-target branches from being merged into matching branches.
func NewTagNamePatternRule(params *RulePatternParameters) (rule *RepositoryRule) {
	bytes, _ := json.Marshal(params)

	rawParams := json.RawMessage(bytes)

	return &RepositoryRule{
		Type:       "tag_name_pattern",
		Parameters: &rawParams,
	}
}

// NewRequiredWorkflowsRule creates a rule to require which status checks must pass before branches can be merged into a branch rule.
func NewRequiredWorkflowsRule(params *RequiredWorkflowsRuleParameters) (rule *RepositoryRule) {
	bytes, _ := json.Marshal(params)

	rawParams := json.RawMessage(bytes)

	return &RepositoryRule{
		Type:       "workflows",
		Parameters: &rawParams,
	}
}

// NewRequiredCodeScanningRule creates a rule to require which tools must provide code scanning results before the reference is updated.
func NewRequiredCodeScanningRule(params *RequiredCodeScanningRuleParameters) (rule *RepositoryRule) {
	bytes, _ := json.Marshal(params)

	rawParams := json.RawMessage(bytes)

	return &RepositoryRule{
		Type:       "code_scanning",
		Parameters: &rawParams,
	}
}

// NewFilePathRestrictionRule creates a rule to restrict file paths from being pushed to.
func NewFilePathRestrictionRule(params *RuleFileParameters) (rule *RepositoryRule) {
	bytes, _ := json.Marshal(params)

	rawParams := json.RawMessage(bytes)

	return &RepositoryRule{
		Type:       "file_path_restriction",
		Parameters: &rawParams,
	}
}

// NewMaxFilePathLengthRule creates a rule to restrict file paths longer than the limit from being pushed.
func NewMaxFilePathLengthRule(params *RuleMaxFilePathLengthParameters) (rule *RepositoryRule) {
	bytes, _ := json.Marshal(params)

	rawParams := json.RawMessage(bytes)

	return &RepositoryRule{
		Type:       "max_file_path_length",
		Parameters: &rawParams,
	}
}

// NewFileExtensionRestrictionRule creates a rule to restrict file extensions from being pushed to a commit.
func NewFileExtensionRestrictionRule(params *RuleFileExtensionRestrictionParameters) (rule *RepositoryRule) {
	bytes, _ := json.Marshal(params)

	rawParams := json.RawMessage(bytes)

	return &RepositoryRule{
		Type:       "file_extension_restriction",
		Parameters: &rawParams,
	}
}

// NewMaxFileSizeRule creates a rule to restrict file sizes from being pushed to a commit.
func NewMaxFileSizeRule(params *RuleMaxFileSizeParameters) (rule *RepositoryRule) {
	bytes, _ := json.Marshal(params)

	rawParams := json.RawMessage(bytes)

	return &RepositoryRule{
		Type:       "max_file_size",
		Parameters: &rawParams,
	}
}

// Ruleset represents a GitHub ruleset object.
type Ruleset struct {
	ID   *int64 `json:"id,omitempty"`
	Name string `json:"name"`
	// Possible values for Target are branch, tag, push
	Target *string `json:"target,omitempty"`
	// Possible values for SourceType are: Repository, Organization
	SourceType *string `json:"source_type,omitempty"`
	Source     string  `json:"source"`
	// Possible values for Enforcement are: disabled, active, evaluate
	Enforcement  string             `json:"enforcement"`
	BypassActors []*BypassActor     `json:"bypass_actors,omitempty"`
	NodeID       *string            `json:"node_id,omitempty"`
	Links        *RulesetLinks      `json:"_links,omitempty"`
	Conditions   *RulesetConditions `json:"conditions,omitempty"`
	Rules        []*RepositoryRule  `json:"rules,omitempty"`
	UpdatedAt    *Timestamp         `json:"updated_at,omitempty"`
	CreatedAt    *Timestamp         `json:"created_at,omitempty"`
}

// rulesetNoOmitBypassActors represents a GitHub ruleset object. The struct does not omit bypassActors if the field is nil or an empty array is passed.
type rulesetNoOmitBypassActors struct {
	ID   *int64 `json:"id,omitempty"`
	Name string `json:"name"`
	// Possible values for Target are branch, tag
	Target *string `json:"target,omitempty"`
	// Possible values for SourceType are: Repository, Organization
	SourceType *string `json:"source_type,omitempty"`
	Source     string  `json:"source"`
	// Possible values for Enforcement are: disabled, active, evaluate
	Enforcement  string             `json:"enforcement"`
	BypassActors []*BypassActor     `json:"bypass_actors"`
	NodeID       *string            `json:"node_id,omitempty"`
	Links        *RulesetLinks      `json:"_links,omitempty"`
	Conditions   *RulesetConditions `json:"conditions,omitempty"`
	Rules        []*RepositoryRule  `json:"rules,omitempty"`
}

// GetRulesForBranch gets all the rules that apply to the specified branch.
//
// GitHub API docs: https://docs.github.com/rest/repos/rules#get-rules-for-a-branch
//
//meta:operation GET /repos/{owner}/{repo}/rules/branches/{branch}
func (s *RepositoriesService) GetRulesForBranch(ctx context.Context, owner, repo, branch string) ([]*RepositoryRule, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/rules/branches/%v", owner, repo, branch)

	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	var rules []*RepositoryRule
	resp, err := s.client.Do(ctx, req, &rules)
	if err != nil {
		return nil, resp, err
	}

	return rules, resp, nil
}

// GetAllRulesets gets all the rules that apply to the specified repository.
// If includesParents is true, rulesets configured at the organization level that apply to the repository will be returned.
//
// GitHub API docs: https://docs.github.com/rest/repos/rules#get-all-repository-rulesets
//
//meta:operation GET /repos/{owner}/{repo}/rulesets
func (s *RepositoriesService) GetAllRulesets(ctx context.Context, owner, repo string, includesParents bool) ([]*Ruleset, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/rulesets?includes_parents=%v", owner, repo, includesParents)

	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	var ruleset []*Ruleset
	resp, err := s.client.Do(ctx, req, &ruleset)
	if err != nil {
		return nil, resp, err
	}

	return ruleset, resp, nil
}

// CreateRuleset creates a ruleset for the specified repository.
//
// GitHub API docs: https://docs.github.com/rest/repos/rules#create-a-repository-ruleset
//
//meta:operation POST /repos/{owner}/{repo}/rulesets
func (s *RepositoriesService) CreateRuleset(ctx context.Context, owner, repo string, rs *Ruleset) (*Ruleset, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/rulesets", owner, repo)

	req, err := s.client.NewRequest("POST", u, rs)
	if err != nil {
		return nil, nil, err
	}

	var ruleset *Ruleset
	resp, err := s.client.Do(ctx, req, &ruleset)
	if err != nil {
		return nil, resp, err
	}

	return ruleset, resp, nil
}

// GetRuleset gets a ruleset for the specified repository.
// If includesParents is true, rulesets configured at the organization level that apply to the repository will be returned.
//
// GitHub API docs: https://docs.github.com/rest/repos/rules#get-a-repository-ruleset
//
//meta:operation GET /repos/{owner}/{repo}/rulesets/{ruleset_id}
func (s *RepositoriesService) GetRuleset(ctx context.Context, owner, repo string, rulesetID int64, includesParents bool) (*Ruleset, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/rulesets/%v?includes_parents=%v", owner, repo, rulesetID, includesParents)

	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	var ruleset *Ruleset
	resp, err := s.client.Do(ctx, req, &ruleset)
	if err != nil {
		return nil, resp, err
	}

	return ruleset, resp, nil
}

// UpdateRuleset updates a ruleset for the specified repository.
//
// GitHub API docs: https://docs.github.com/rest/repos/rules#update-a-repository-ruleset
//
//meta:operation PUT /repos/{owner}/{repo}/rulesets/{ruleset_id}
func (s *RepositoriesService) UpdateRuleset(ctx context.Context, owner, repo string, rulesetID int64, rs *Ruleset) (*Ruleset, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/rulesets/%v", owner, repo, rulesetID)

	req, err := s.client.NewRequest("PUT", u, rs)
	if err != nil {
		return nil, nil, err
	}

	var ruleset *Ruleset
	resp, err := s.client.Do(ctx, req, &ruleset)
	if err != nil {
		return nil, resp, err
	}

	return ruleset, resp, nil
}

// UpdateRulesetNoBypassActor updates a ruleset for the specified repository.
//
// This function is necessary as the UpdateRuleset function does not marshal ByPassActor if passed as nil or an empty array.
//
// GitHub API docs: https://docs.github.com/rest/repos/rules#update-a-repository-ruleset
//
//meta:operation PUT /repos/{owner}/{repo}/rulesets/{ruleset_id}
func (s *RepositoriesService) UpdateRulesetNoBypassActor(ctx context.Context, owner, repo string, rulesetID int64, rs *Ruleset) (*Ruleset, *Response, error) {
	u := fmt.Sprintf("repos/%v/%v/rulesets/%v", owner, repo, rulesetID)

	rsNoBypassActor := &rulesetNoOmitBypassActors{}

	if rs != nil {
		rsNoBypassActor = &rulesetNoOmitBypassActors{
			ID:           rs.ID,
			Name:         rs.Name,
			Target:       rs.Target,
			SourceType:   rs.SourceType,
			Source:       rs.Source,
			Enforcement:  rs.Enforcement,
			BypassActors: rs.BypassActors,
			NodeID:       rs.NodeID,
			Links:        rs.Links,
			Conditions:   rs.Conditions,
			Rules:        rs.Rules,
		}
	}

	req, err := s.client.NewRequest("PUT", u, rsNoBypassActor)
	if err != nil {
		return nil, nil, err
	}

	var ruleSet *Ruleset
	resp, err := s.client.Do(ctx, req, &ruleSet)
	if err != nil {
		return nil, resp, err
	}

	return ruleSet, resp, nil
}

// DeleteRuleset deletes a ruleset for the specified repository.
//
// GitHub API docs: https://docs.github.com/rest/repos/rules#delete-a-repository-ruleset
//
//meta:operation DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}
func (s *RepositoriesService) DeleteRuleset(ctx context.Context, owner, repo string, rulesetID int64) (*Response, error) {
	u := fmt.Sprintf("repos/%v/%v/rulesets/%v", owner, repo, rulesetID)

	req, err := s.client.NewRequest("DELETE", u, nil)
	if err != nil {
		return nil, err
	}

	return s.client.Do(ctx, req, nil)
}
