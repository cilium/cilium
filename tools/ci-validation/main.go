// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// ci-validation flags pull requests whose CI changes are not exercised by the
// pull request's own CI, so that a reviewer validates them manually before
// merge. See Documentation/contributing/testing/ci.rst for the process.
//
// It is meant to be run from the ci-validation workflow, and never checks out
// or executes the pull request's head: the workflows it classifies are fetched
// through the API as data.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-github/v90/github"
)

type config struct {
	owner   string
	repo    string
	number  int
	headSHA string
	token   string
	dryRun  bool
}

func loadConfig() (*config, error) {
	cfg := &config{
		headSHA: os.Getenv("HEAD_SHA"),
		token:   os.Getenv("GITHUB_TOKEN"),
	}
	flag.BoolVar(&cfg.dryRun, "dry-run", false,
		"report what would be done without labelling or commenting")
	flag.Parse()

	repository := os.Getenv("GITHUB_REPOSITORY")
	owner, repo, ok := strings.Cut(repository, "/")
	if !ok {
		return nil, fmt.Errorf("GITHUB_REPOSITORY is not in owner/repo form: %q", repository)
	}
	cfg.owner, cfg.repo = owner, repo

	number, err := strconv.Atoi(os.Getenv("PR_NUMBER"))
	if err != nil {
		return nil, fmt.Errorf("parsing PR_NUMBER: %w", err)
	}
	cfg.number = number

	if cfg.headSHA == "" {
		return nil, fmt.Errorf("HEAD_SHA is not set")
	}
	if cfg.token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN is not set")
	}
	return cfg, nil
}

func main() {
	log.SetFlags(0)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}
	if err := run(context.Background(), cfg); err != nil {
		log.Fatalf("Failed to check for unvalidated CI changes: %v", err)
	}
}

func run(ctx context.Context, cfg *config) error {
	client, err := github.NewClient(github.WithAuthToken(cfg.token))
	if err != nil {
		return fmt.Errorf("creating GitHub client: %w", err)
	}

	// Page at the maximum size: this runs on every push to every pull request,
	// and the default of 30 costs a request per 30 files or comments.
	listOpts := github.ListOptions{PerPage: 100}

	var changed []string
	for file, err := range client.PullRequests.ListFilesIter(ctx, cfg.owner, cfg.repo, cfg.number, &listOpts) {
		if err != nil {
			return fmt.Errorf("listing pull request files: %w", err)
		}
		if file.GetStatus() != "removed" {
			changed = append(changed, file.GetFilename())
		}
	}

	fetch := func(path string) ([]byte, error) {
		content, _, _, err := client.Repositories.GetContents(ctx, cfg.owner, cfg.repo, path,
			&github.RepositoryContentGetOptions{Ref: cfg.headSHA})
		if err != nil {
			return nil, err
		}
		if content == nil {
			return nil, fmt.Errorf("%s is not a file", path)
		}
		decoded, err := content.GetContent()
		if err != nil {
			return nil, err
		}
		return []byte(decoded), nil
	}

	unvalidated := unvalidatedPaths(changed, fetch, log.Printf)
	if len(unvalidated) == 0 {
		log.Print("No unvalidated CI changes detected.")
		return nil
	}
	log.Printf("Unvalidated CI changes: %s", strings.Join(paths(unvalidated), ", "))

	// Whether the pull request comes from a fork decides how its CI changes can
	// be validated, because Ariane dispatches, and checks out, the pull
	// request's own branch only when that branch is in this repository.
	pr, _, err := client.PullRequests.Get(ctx, cfg.owner, cfg.repo, cfg.number)
	if err != nil {
		return fmt.Errorf("getting the pull request: %w", err)
	}
	prCtx := prContext{
		number:     cfg.number,
		headSHA:    cfg.headSHA,
		baseSHA:    pr.GetBase().GetSHA(),
		baseBranch: pr.GetBase().GetRef(),
	}
	fromFork := pr.GetHead().GetRepo().GetFullName() != cfg.owner+"/"+cfg.repo
	log.Printf("Pull request head is %s (fork: %t), base %s",
		pr.GetHead().GetRepo().GetFullName(), fromFork, prCtx.baseBranch)

	// Read from the checkout, which is the base branch and so trusted, to work
	// out which workflows consume the changed files and what dispatches them.
	workflows, err := loadWorkflows(workflowsDir)
	if err != nil {
		return err
	}
	arianeConfig, err := os.ReadFile(arianeConfigFile)
	if err != nil {
		return fmt.Errorf("reading %s: %w", arianeConfigFile, err)
	}
	triggers, err := arianeTriggers(arianeConfig)
	if err != nil {
		return err
	}

	var comments []comment
	for c, err := range client.Issues.ListCommentsIter(ctx, cfg.owner, cfg.repo, cfg.number,
		&github.IssueListCommentsOptions{ListOptions: listOpts}) {
		if err != nil {
			return fmt.Errorf("listing comments: %w", err)
		}
		comments = append(comments, comment{
			body:  c.GetBody(),
			isBot: c.GetUser().GetType() == "Bot",
		})
	}

	reported := reportedPaths(comments, log.Printf)
	fresh := freshFindings(unvalidated, reported)
	if len(fresh) == 0 {
		log.Print("All unvalidated CI changes have already been reported.")
		return nil
	}
	log.Printf("Newly reported CI changes: %s", strings.Join(paths(fresh), ", "))

	steps := plan(fresh, workflows, triggers, fromFork)
	body := renderNotice(steps, paths(unvalidated), len(reported) > 0, prCtx)
	if cfg.dryRun {
		log.Printf("Dry run, would apply %q and post this comment:", validationLabel)
		log.Print(body)
		return nil
	}

	if _, _, err := client.Issues.AddLabelsToIssue(ctx, cfg.owner, cfg.repo, cfg.number,
		[]string{validationLabel}); err != nil {
		return fmt.Errorf("applying the %s label: %w", validationLabel, err)
	}
	if _, _, err := client.Issues.CreateComment(ctx, cfg.owner, cfg.repo, cfg.number,
		&github.IssueComment{Body: github.Ptr(body)}); err != nil {
		return fmt.Errorf("posting the notice: %w", err)
	}
	return nil
}
