// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/cilium-cli/defaults"

	"github.com/google/go-github/v71/github"
	"golang.org/x/oauth2"
)

type perJobMetrics map[string]perDeployNodeMetrics
type perWorkflowMetrics map[string]perJobMetrics

// GenSummary downloads and generates a summary table with all the features
// tested in the CI run.
func (s *Feature) GenSummary(ctx context.Context) error {
	err := s.downloadWorkflowData(ctx)
	if err != nil {
		return fmt.Errorf("downloading workflow data: %w", err)
	}

	workflowData, err := loadWorkflowData(s.params.MetricsDirectory)
	if err != nil {
		return err
	}
	return s.printSummaryFromJsons(workflowData)
}

func (s *Feature) downloadWorkflowData(ctx context.Context) error {
	token := os.Getenv("GITHUB_TOKEN")

	if token == "" {
		return fmt.Errorf("GITHUB_TOKEN environment variable must be set.")
	}

	parts := strings.Split(s.params.Repo, "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid repository format. Expected 'owner/repo', got '%s'", s.params.Repo)
	}
	owner, repoName := parts[0], parts[1]

	tc := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
	ghClient := github.NewClient(tc)

	allRuns := map[int64]*github.WorkflowRun{}
	// Fetch workflow runs for the specific commit
	for _, event := range []string{"push", "schedule", "pull_request", "pull_request_target"} {
		opts := &github.ListWorkflowRunsOptions{
			HeadSHA: s.params.Commit,
			Status:  "completed",
			Event:   event,
			ListOptions: github.ListOptions{
				PerPage: 100,
			},
		}

		for {
			runs, resp, err := ghClient.Actions.ListRepositoryWorkflowRuns(ctx, owner, repoName, opts)
			if err != nil {
				return fmt.Errorf("failed to fetch workflow runs: %w", err)
			}
			for _, run := range runs.WorkflowRuns {
				allRuns[run.GetID()] = run
			}
			if resp.NextPage == 0 {
				break
			}
			opts.Page = resp.NextPage
		}
	}

	// Fetch also the workflow runs from commit status. (The ones populated by
	// ariane)
	opts := &github.ListOptions{
		PerPage: 100,
	}
	for {
		status, resp, err := ghClient.Repositories.GetCombinedStatus(ctx, owner, repoName, s.params.Commit, opts)
		if err != nil {
			return fmt.Errorf("error retrieving status check for commit %s: %w", s.params.Commit, err)
		}

		for _, st := range status.Statuses {
			// Just check the status from GH actions, which have the URL from
			// github.com
			if !strings.HasPrefix(st.GetTargetURL(), "https://github.com/"+s.params.Repo) {
				continue
			}
			runIDStr := path.Base(st.GetTargetURL())
			runID, err := strconv.ParseUint(runIDStr, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid run ID %s: %w", runIDStr, err)
			}
			run, _, err := ghClient.Actions.GetWorkflowRunByID(ctx, owner, repoName, int64(runID))
			if err != nil {
				return fmt.Errorf("failed to list workflow for ID %d: %w", runID, err)
			}
			allRuns[run.GetID()] = run
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	var allRunsSorted []*github.WorkflowRun
	for _, run := range allRuns {
		allRunsSorted = append(allRunsSorted, run)
	}
	sort.Slice(allRunsSorted, func(i, j int) bool {
		return allRunsSorted[i].GetID() < allRunsSorted[j].GetID()
	})

	// Process each workflow run by order, if there's another scheduled workflow
	// run it can overwrite previous runs.
	for _, run := range allRunsSorted {
		runID := run.GetID()
		runName := run.GetName()
		fmt.Fprintf(os.Stderr, "Processing workflow run: %s (ID: %d)\n", runName, runID)

		// Download artifacts for the workflow run
		err := downloadArtifacts(ctx, ghClient, owner, repoName, runID, "features-tested*", filepath.Join(s.params.MetricsDirectory, runName))
		if err != nil {
			return fmt.Errorf("failed to download artifacts for run %d: %w", runID, err)
		}
	}
	return nil
}

// downloadArtifacts downloads all artifacts for a given workflow run and saves
// files matching the pattern to the specified directory.
func downloadArtifacts(ctx context.Context, client *github.Client, owner, repo string, runID int64, pattern, destDir string) error {
	artifacts, _, err := client.Actions.ListWorkflowRunArtifacts(ctx, owner, repo, runID, &github.ListOptions{PerPage: 100})
	if err != nil {
		return fmt.Errorf("failed to list artifacts for run %d: %w", runID, err)
	}

	if len(artifacts.Artifacts) == 0 {
		fmt.Fprintf(os.Stderr, " - ARTIFACTS NOT FOUND %d\n", runID)
		return nil
	}

	// Create destination directory if it doesn't exist
	if err := os.MkdirAll(destDir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", destDir, err)
	}

	// Download and extract matching artifacts
	for _, artifact := range artifacts.Artifacts {
		if matched, _ := filepath.Match(pattern, artifact.GetName()); !matched {
			continue
		}

		fmt.Fprintf(os.Stderr, " - Downloading artifact: %s (ID: %d)\n", artifact.GetName(), artifact.GetID())

		// Get the artifact download URL
		archiveURL, _, err := client.Actions.DownloadArtifact(ctx, owner, repo, artifact.GetID(), 5)
		if err != nil {
			return fmt.Errorf("failed to get download URL for artifact %d: %w", artifact.GetID(), err)
		}

		// Download the artifact
		resp, err := http.Get(archiveURL.String())
		if err != nil {
			return fmt.Errorf("failed to download artifact %d: %w", artifact.GetID(), err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code %d for artifact %d", resp.StatusCode, artifact.GetID())
		}

		// Save the artifact to a temporary ZIP file
		tempFile := filepath.Join(destDir, fmt.Sprintf("%s.zip", artifact.GetName()))
		out, err := os.Create(tempFile)
		if err != nil {
			return fmt.Errorf("failed to create temp file %s: %w", tempFile, err)
		}

		_, err = io.Copy(out, resp.Body)
		out.Close()
		if err != nil {
			return fmt.Errorf("failed to save artifact to %s: %w", tempFile, err)
		}

		// Extract the ZIP file to the destination directory
		err = extractZip(tempFile, destDir)
		if err != nil {
			return fmt.Errorf("failed to extract artifact %s: %w", tempFile, err)
		}

		// Clean up the temporary ZIP file
		os.Remove(tempFile)
	}

	return nil
}

// extractZip extracts the contents of a ZIP file to a specified directory.
func extractZip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open ZIP file %s: %w", zipPath, err)
	}
	defer r.Close()

	for _, file := range r.File {
		destPath := filepath.Join(destDir, file.Name)
		if file.FileInfo().IsDir() {
			// Create directories
			if err := os.MkdirAll(destPath, os.ModePerm); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", destPath, err)
			}
			continue
		}

		// Extract files
		destFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			return fmt.Errorf("failed to create file %s: %w", destPath, err)
		}
		srcFile, err := file.Open()
		if err != nil {
			destFile.Close()
			return fmt.Errorf("failed to open file in ZIP archive %s: %w", file.Name, err)
		}
		_, err = io.Copy(destFile, srcFile)
		destFile.Close()
		srcFile.Close()
		if err != nil {
			return fmt.Errorf("failed to extract file %s: %w", file.Name, err)
		}
	}

	return nil
}

// nodesValues maps a node to value
type nodesValues map[string]float64

// job maps a job to nodes
type jobNodes map[string]nodesValues

// workflowNodes maps a workflow name to jobs
type workflowNodes map[string]jobNodes

// metricsWorkflows maps a metric name to workflows
type metricsWorkflows map[string]workflowNodes

func (s *Feature) printSummaryFromJsons(workflowData perWorkflowMetrics) error {
	result := make(metricsWorkflows)
	metricNamesSet := map[string]struct{}{}
	workflows := map[string]struct{}{}

	// Process each workflow and its nodes
	for workflow, jobs := range workflowData {
		workflows[workflow] = struct{}{}

		for jobName, nodes := range jobs {
			for nodeName, deployMetrics := range nodes {
				for _, deploymentMetrics := range deployMetrics {
					for _, d := range deploymentMetrics {
						metricNames := d.Name
						var orderedLabels []string
						for k, v := range d.Labels {
							orderedLabels = append(orderedLabels, fmt.Sprintf("%s=%s", k, v))
						}
						slices.Sort(orderedLabels)
						if len(orderedLabels) != 0 {
							metricNames += ";"
						}
						metricNames += strings.Join(orderedLabels, ";")

						if _, ok := result[metricNames]; !ok {
							result[metricNames] = make(workflowNodes)
						}
						if _, ok := result[metricNames][workflow]; !ok {
							result[metricNames][workflow] = make(jobNodes)
						}
						if _, ok := result[metricNames][workflow][jobName]; !ok {
							result[metricNames][workflow][jobName] = make(nodesValues)
						}
						result[metricNames][workflow][jobName][nodeName] = d.Value
						metricNamesSet[metricNames] = struct{}{}
					}
				}
			}
		}
	}
	metricNamesSorted := slices.Sorted(maps.Keys(metricNamesSet))

	// Generate markdown for the summary table
	detailsBuilder := &bytes.Buffer{}
	fmt.Fprintf(detailsBuilder, "## Summary Table\n\n")
	fmt.Fprintf(detailsBuilder, "| Tested on >=1 workflow? | Metric                             | Labels                      | Details Link                                       |\n")
	fmt.Fprintf(detailsBuilder, "|-------------------------|------------------------------------|-----------------------------|----------------------------------------------------|\n")

	testedOnOneWorkflow := map[string]struct{}{}
	for _, metricKeys := range metricNamesSorted {
		name, labels := parseNameAndLabels(metricKeys)
		var hasValue bool
		for workflow := range workflows {
			for _, nodesMetrics := range result[metricKeys][workflow] {
				for _, value := range nodesMetrics {
					if value > 0 {
						hasValue = true
						testedOnOneWorkflow[metricKeys] = struct{}{}
						break
					}
				}
				if hasValue {
					break
				}
			}
			if hasValue {
				break
			}
		}
		var detailsLink string
		if hasValue {
			// GH Step summary prefixes all anchors with "user-content-". This
			// workaround allows use to make the anchors usable.
			var anchorPrefix string
			if s.params.GHStepSummaryAnchor {
				anchorPrefix = "user-content-"
			}
			detailsLink = fmt.Sprintf("[View Details](#%smetric-%s)", anchorPrefix, pathEscape(metricKeys))
		}
		fmt.Fprintf(detailsBuilder, "| %-22s | %-34s | %-27s | %-50s |\n", boolToStr(hasValue), strings.ReplaceAll(name, "cilium_feature_", ""), labels, detailsLink)
	}

	var printFootnote bool
	for _, metricName := range metricNamesSorted {
		if _, ok := testedOnOneWorkflow[metricName]; !ok {
			continue
		}
		name, labels := parseNameAndLabels(metricName)

		fmt.Fprintf(detailsBuilder, "\n<a name='metric-%s'></a>", pathEscape(metricName))
		fmt.Fprintf(detailsBuilder, "\n### Metric: `%s`\n", name)
		if labels != "" {
			fmt.Fprintf(detailsBuilder, "- **Labels**: `%s`\n\n", labels)
		}
		fmt.Fprintf(detailsBuilder, "<details>\n")
		fmt.Fprintf(detailsBuilder, "<summary>Click here to see</summary>\n\n\n\n")

		//  metric+label / workflow / jobs / nodes / value
		metricsPerWorkflow := result[metricName]

		orderedWorkflows := slices.Sorted(maps.Keys(metricsPerWorkflow))

		var printJob string

		for _, workflow := range orderedWorkflows {
			metricsPerJob := metricsPerWorkflow[workflow]
			if len(metricsPerJob) == 0 {
				continue
			}
			printJobDetails := true
			orderedJobs := slices.Sorted(maps.Keys(metricsPerJob))
			for _, job := range orderedJobs {
				printJob = job
				orderedNodes := slices.Sorted(maps.Keys(metricsPerJob[job]))
				previousValue := -1.0
				isFirst := true
				allEqual := true
				for _, nodeName := range orderedNodes {
					value := metricsPerJob[job][nodeName]
					if value == 0 {
						continue
					}
					if isFirst {
						previousValue = value
						isFirst = false
					} else if value != previousValue {
						allEqual = false
						break
					}
				}
				if previousValue == -1.0 {
					continue
				}
				if printJobDetails {
					fmt.Fprintf(detailsBuilder, "#### **%s**\n\n", workflow)
					fmt.Fprintf(detailsBuilder, "| Job   | Value |\n")
					fmt.Fprintf(detailsBuilder, "|-------|-------|\n")
					printJobDetails = false
				}
				if printJob == job {
					fmt.Fprintf(detailsBuilder, "| %-13s ", printJob)
					printJob = ""
				} else {
					fmt.Fprintf(detailsBuilder, "| %-13s ", "")
				}
				if allEqual {
					fmt.Fprintf(detailsBuilder, "| %-5.0f |\n", previousValue)
				} else {
					fmt.Fprintf(detailsBuilder, "| ⚠ [^1] |\n")
					printFootnote = true
				}
			}
		}

		fmt.Fprintf(detailsBuilder, "</details>\n")
	}

	if printFootnote {
		fmt.Fprintf(detailsBuilder, "[^1]: Nodes on this test had different values across themselves\n")
	}

	f, err := os.OpenFile(s.params.Outputfile, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("unable to open file %w", err)
	}
	defer f.Close()
	_, err = detailsBuilder.WriteTo(f)
	if err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}
	return nil
}

func boolToStr(b bool) string {
	if b {
		return "✅"
	}
	return "❌"
}

func pathEscape(s string) string {
	return strings.NewReplacer(" ", "_", ";", "-").Replace(s)
}

// Function to load workflow data from JSON files
func loadWorkflowData(directory string) (perWorkflowMetrics, error) {
	workflowData := make(perWorkflowMetrics)

	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && filepath.Ext(path) == ".json" {
			fileData, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("error reading file %q: %w", path, err)
			}
			var nodesData perDeployNodeMetrics
			err = json.Unmarshal(fileData, &nodesData)
			if err != nil {
				// Because the runtime tests are running on a single node,
				// they will only have a list of metrics stored on each .json
				// file
				var errUTE *json.UnmarshalTypeError
				if !errors.As(err, &errUTE) {
					return fmt.Errorf("error unmarshalling file %q: %w", path, err)
				}
				var metrics []*models.Metric
				err = json.Unmarshal(fileData, &metrics)
				if err != nil {
					return fmt.Errorf("error unmarshalling file %q: %w", path, err)
				}
				nodesData = perDeployNodeMetrics{
					defaults.AgentDaemonSetName: perNodeMetrics{
						"runtime": metrics,
					},
				}
			}

			// Get workflow name (parent directory) and node name (file name without extension)
			workflowName := filepath.Base(filepath.Dir(path))
			jobName := info.Name()[:len(info.Name())-len(filepath.Ext(info.Name()))]

			// Initialize workflow entry if it doesn't exist
			if _, exists := workflowData[workflowName]; !exists {
				workflowData[workflowName] = make(perJobMetrics)
			}

			// Add node data to the workflow's node entry
			workflowData[workflowName][jobName] = nodesData
		}

		return nil
	})

	return workflowData, err
}
