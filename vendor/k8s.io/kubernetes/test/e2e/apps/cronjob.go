/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package apps

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/pkg/api"
	batchinternal "k8s.io/kubernetes/pkg/apis/batch"
	"k8s.io/kubernetes/pkg/controller/job"
	"k8s.io/kubernetes/pkg/kubectl"
	"k8s.io/kubernetes/test/e2e/framework"
	imageutils "k8s.io/kubernetes/test/utils/image"
)

const (
	// How long to wait for a cronjob
	cronJobTimeout = 5 * time.Minute
)

var _ = SIGDescribe("CronJob", func() {
	f := framework.NewDefaultFramework("cronjob")

	sleepCommand := []string{"sleep", "300"}

	// Pod will complete instantly
	successCommand := []string{"/bin/true"}

	BeforeEach(func() {
		framework.SkipIfMissingResource(f.ClientPool, CronJobGroupVersionResourceBeta, f.Namespace.Name)
	})

	// multiple jobs running at once
	It("should schedule multiple jobs concurrently", func() {
		By("Creating a cronjob")
		cronJob := newTestCronJob("concurrent", "*/1 * * * ?", batchv1beta1.AllowConcurrent,
			sleepCommand, nil)
		cronJob, err := createCronJob(f.ClientSet, f.Namespace.Name, cronJob)
		Expect(err).NotTo(HaveOccurred())

		By("Ensuring more than one job is running at a time")
		err = waitForActiveJobs(f.ClientSet, f.Namespace.Name, cronJob.Name, 2)
		Expect(err).NotTo(HaveOccurred())

		By("Ensuring at least two running jobs exists by listing jobs explicitly")
		jobs, err := f.ClientSet.Batch().Jobs(f.Namespace.Name).List(metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
		activeJobs, _ := filterActiveJobs(jobs)
		Expect(len(activeJobs) >= 2).To(BeTrue())

		By("Removing cronjob")
		err = deleteCronJob(f.ClientSet, f.Namespace.Name, cronJob.Name)
		Expect(err).NotTo(HaveOccurred())
	})

	// suspended should not schedule jobs
	It("should not schedule jobs when suspended [Slow]", func() {
		By("Creating a suspended cronjob")
		cronJob := newTestCronJob("suspended", "*/1 * * * ?", batchv1beta1.AllowConcurrent,
			sleepCommand, nil)
		t := true
		cronJob.Spec.Suspend = &t
		cronJob, err := createCronJob(f.ClientSet, f.Namespace.Name, cronJob)
		Expect(err).NotTo(HaveOccurred())

		By("Ensuring no jobs are scheduled")
		err = waitForNoJobs(f.ClientSet, f.Namespace.Name, cronJob.Name, false)
		Expect(err).To(HaveOccurred())

		By("Ensuring no job exists by listing jobs explicitly")
		jobs, err := f.ClientSet.Batch().Jobs(f.Namespace.Name).List(metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(jobs.Items).To(HaveLen(0))

		By("Removing cronjob")
		err = deleteCronJob(f.ClientSet, f.Namespace.Name, cronJob.Name)
		Expect(err).NotTo(HaveOccurred())
	})

	// only single active job is allowed for ForbidConcurrent
	It("should not schedule new jobs when ForbidConcurrent [Slow]", func() {
		By("Creating a ForbidConcurrent cronjob")
		cronJob := newTestCronJob("forbid", "*/1 * * * ?", batchv1beta1.ForbidConcurrent,
			sleepCommand, nil)
		cronJob, err := createCronJob(f.ClientSet, f.Namespace.Name, cronJob)
		Expect(err).NotTo(HaveOccurred())

		By("Ensuring a job is scheduled")
		err = waitForActiveJobs(f.ClientSet, f.Namespace.Name, cronJob.Name, 1)
		Expect(err).NotTo(HaveOccurred())

		By("Ensuring exactly one is scheduled")
		cronJob, err = getCronJob(f.ClientSet, f.Namespace.Name, cronJob.Name)
		Expect(err).NotTo(HaveOccurred())
		Expect(cronJob.Status.Active).Should(HaveLen(1))

		By("Ensuring exactly one running job exists by listing jobs explicitly")
		jobs, err := f.ClientSet.Batch().Jobs(f.Namespace.Name).List(metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
		activeJobs, _ := filterActiveJobs(jobs)
		Expect(activeJobs).To(HaveLen(1))

		By("Ensuring no more jobs are scheduled")
		err = waitForActiveJobs(f.ClientSet, f.Namespace.Name, cronJob.Name, 2)
		Expect(err).To(HaveOccurred())

		By("Removing cronjob")
		err = deleteCronJob(f.ClientSet, f.Namespace.Name, cronJob.Name)
		Expect(err).NotTo(HaveOccurred())
	})

	// only single active job is allowed for ReplaceConcurrent
	It("should replace jobs when ReplaceConcurrent", func() {
		By("Creating a ReplaceConcurrent cronjob")
		cronJob := newTestCronJob("replace", "*/1 * * * ?", batchv1beta1.ReplaceConcurrent,
			sleepCommand, nil)
		cronJob, err := createCronJob(f.ClientSet, f.Namespace.Name, cronJob)
		Expect(err).NotTo(HaveOccurred())

		By("Ensuring a job is scheduled")
		err = waitForActiveJobs(f.ClientSet, f.Namespace.Name, cronJob.Name, 1)
		Expect(err).NotTo(HaveOccurred())

		By("Ensuring exactly one is scheduled")
		cronJob, err = getCronJob(f.ClientSet, f.Namespace.Name, cronJob.Name)
		Expect(err).NotTo(HaveOccurred())
		Expect(cronJob.Status.Active).Should(HaveLen(1))

		By("Ensuring exactly one running job exists by listing jobs explicitly")
		jobs, err := f.ClientSet.Batch().Jobs(f.Namespace.Name).List(metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
		activeJobs, _ := filterActiveJobs(jobs)
		Expect(activeJobs).To(HaveLen(1))

		By("Ensuring the job is replaced with a new one")
		err = waitForJobReplaced(f.ClientSet, f.Namespace.Name, jobs.Items[0].Name)
		Expect(err).NotTo(HaveOccurred())

		By("Removing cronjob")
		err = deleteCronJob(f.ClientSet, f.Namespace.Name, cronJob.Name)
		Expect(err).NotTo(HaveOccurred())
	})

	// shouldn't give us unexpected warnings
	It("should not emit unexpected warnings", func() {
		By("Creating a cronjob")
		cronJob := newTestCronJob("concurrent", "*/1 * * * ?", batchv1beta1.AllowConcurrent,
			nil, nil)
		cronJob, err := createCronJob(f.ClientSet, f.Namespace.Name, cronJob)
		Expect(err).NotTo(HaveOccurred())

		By("Ensuring at least two jobs and at least one finished job exists by listing jobs explicitly")
		err = waitForJobsAtLeast(f.ClientSet, f.Namespace.Name, 2)
		Expect(err).NotTo(HaveOccurred())
		err = waitForAnyFinishedJob(f.ClientSet, f.Namespace.Name)
		Expect(err).NotTo(HaveOccurred())

		By("Ensuring no unexpected event has happened")
		err = checkNoEventWithReason(f.ClientSet, f.Namespace.Name, cronJob.Name, []string{"MissingJob", "UnexpectedJob"})
		Expect(err).NotTo(HaveOccurred())

		By("Removing cronjob")
		err = deleteCronJob(f.ClientSet, f.Namespace.Name, cronJob.Name)
		Expect(err).NotTo(HaveOccurred())
	})

	// deleted jobs should be removed from the active list
	It("should remove from active list jobs that have been deleted", func() {
		By("Creating a ForbidConcurrent cronjob")
		cronJob := newTestCronJob("forbid", "*/1 * * * ?", batchv1beta1.ForbidConcurrent,
			sleepCommand, nil)
		cronJob, err := createCronJob(f.ClientSet, f.Namespace.Name, cronJob)
		Expect(err).NotTo(HaveOccurred())

		By("Ensuring a job is scheduled")
		err = waitForActiveJobs(f.ClientSet, f.Namespace.Name, cronJob.Name, 1)
		Expect(err).NotTo(HaveOccurred())

		By("Ensuring exactly one is scheduled")
		cronJob, err = getCronJob(f.ClientSet, f.Namespace.Name, cronJob.Name)
		Expect(err).NotTo(HaveOccurred())
		Expect(cronJob.Status.Active).Should(HaveLen(1))

		By("Deleting the job")
		job := cronJob.Status.Active[0]
		reaper, err := kubectl.ReaperFor(batchinternal.Kind("Job"), f.InternalClientset)
		Expect(err).NotTo(HaveOccurred())
		timeout := 1 * time.Minute
		err = reaper.Stop(f.Namespace.Name, job.Name, timeout, metav1.NewDeleteOptions(0))
		Expect(err).NotTo(HaveOccurred())

		By("Ensuring job was deleted")
		_, err = framework.GetJob(f.ClientSet, f.Namespace.Name, job.Name)
		Expect(err).To(HaveOccurred())
		Expect(errors.IsNotFound(err)).To(BeTrue())

		By("Ensuring there are no active jobs in the cronjob")
		err = waitForNoJobs(f.ClientSet, f.Namespace.Name, cronJob.Name, true)
		Expect(err).NotTo(HaveOccurred())

		By("Ensuring MissingJob event has occured")
		err = checkNoEventWithReason(f.ClientSet, f.Namespace.Name, cronJob.Name, []string{"MissingJob"})
		Expect(err).To(HaveOccurred())

		By("Removing cronjob")
		err = deleteCronJob(f.ClientSet, f.Namespace.Name, cronJob.Name)
		Expect(err).NotTo(HaveOccurred())
	})

	// cleanup of successful finished jobs, with limit of one successful job
	It("should delete successful finished jobs with limit of one successful job", func() {
		By("Creating a AllowConcurrent cronjob with custom history limits")
		successLimit := int32(1)
		cronJob := newTestCronJob("concurrent-limit", "*/1 * * * ?", batchv1beta1.AllowConcurrent,
			successCommand, &successLimit)
		cronJob, err := createCronJob(f.ClientSet, f.Namespace.Name, cronJob)
		Expect(err).NotTo(HaveOccurred())

		// Job is going to complete instantly: do not check for an active job
		// as we are most likely to miss it

		By("Ensuring a finished job exists")
		err = waitForAnyFinishedJob(f.ClientSet, f.Namespace.Name)
		Expect(err).NotTo(HaveOccurred())

		By("Ensuring a finished job exists by listing jobs explicitly")
		jobs, err := f.ClientSet.Batch().Jobs(f.Namespace.Name).List(metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
		_, finishedJobs := filterActiveJobs(jobs)
		Expect(len(finishedJobs) == 1).To(BeTrue())

		// Job should get deleted when the next job finishes the next minute
		By("Ensuring this job does not exist anymore")
		err = waitForJobNotExist(f.ClientSet, f.Namespace.Name, finishedJobs[0])
		Expect(err).NotTo(HaveOccurred())

		By("Ensuring there is 1 finished job by listing jobs explicitly")
		jobs, err = f.ClientSet.Batch().Jobs(f.Namespace.Name).List(metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
		_, finishedJobs = filterActiveJobs(jobs)
		Expect(len(finishedJobs) == 1).To(BeTrue())

		By("Removing cronjob")
		err = deleteCronJob(f.ClientSet, f.Namespace.Name, cronJob.Name)
		Expect(err).NotTo(HaveOccurred())
	})
})

// newTestCronJob returns a cronjob which does one of several testing behaviors.
func newTestCronJob(name, schedule string, concurrencyPolicy batchv1beta1.ConcurrencyPolicy,
	command []string, successfulJobsHistoryLimit *int32) *batchv1beta1.CronJob {
	parallelism := int32(1)
	completions := int32(1)
	sj := &batchv1beta1.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		TypeMeta: metav1.TypeMeta{
			Kind: "CronJob",
		},
		Spec: batchv1beta1.CronJobSpec{
			Schedule:          schedule,
			ConcurrencyPolicy: concurrencyPolicy,
			JobTemplate: batchv1beta1.JobTemplateSpec{
				Spec: batchv1.JobSpec{
					Parallelism: &parallelism,
					Completions: &completions,
					Template: v1.PodTemplateSpec{
						Spec: v1.PodSpec{
							RestartPolicy: v1.RestartPolicyOnFailure,
							Volumes: []v1.Volume{
								{
									Name: "data",
									VolumeSource: v1.VolumeSource{
										EmptyDir: &v1.EmptyDirVolumeSource{},
									},
								},
							},
							Containers: []v1.Container{
								{
									Name:  "c",
									Image: imageutils.GetBusyBoxImage(),
									VolumeMounts: []v1.VolumeMount{
										{
											MountPath: "/data",
											Name:      "data",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	sj.Spec.SuccessfulJobsHistoryLimit = successfulJobsHistoryLimit
	if command != nil {
		sj.Spec.JobTemplate.Spec.Template.Spec.Containers[0].Command = command
	}
	return sj
}

func createCronJob(c clientset.Interface, ns string, cronJob *batchv1beta1.CronJob) (*batchv1beta1.CronJob, error) {
	return c.BatchV1beta1().CronJobs(ns).Create(cronJob)
}

func getCronJob(c clientset.Interface, ns, name string) (*batchv1beta1.CronJob, error) {
	return c.BatchV1beta1().CronJobs(ns).Get(name, metav1.GetOptions{})
}

func deleteCronJob(c clientset.Interface, ns, name string) error {
	return c.BatchV1beta1().CronJobs(ns).Delete(name, nil)
}

// Wait for at least given amount of active jobs.
func waitForActiveJobs(c clientset.Interface, ns, cronJobName string, active int) error {
	return wait.Poll(framework.Poll, cronJobTimeout, func() (bool, error) {
		curr, err := c.BatchV1beta1().CronJobs(ns).Get(cronJobName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return len(curr.Status.Active) >= active, nil
	})
}

// Wait for jobs to appear in the active list of a cronjob or not.
// When failIfNonEmpty is set, this fails if the active set of jobs is still non-empty after
// the timeout. When failIfNonEmpty is not set, this fails if the active set of jobs is still
// empty after the timeout.
func waitForNoJobs(c clientset.Interface, ns, jobName string, failIfNonEmpty bool) error {
	return wait.Poll(framework.Poll, cronJobTimeout, func() (bool, error) {
		curr, err := c.BatchV1beta1().CronJobs(ns).Get(jobName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		if failIfNonEmpty {
			return len(curr.Status.Active) == 0, nil
		} else {
			return len(curr.Status.Active) != 0, nil
		}
	})
}

// Wait for a job to not exist by listing jobs explicitly.
func waitForJobNotExist(c clientset.Interface, ns string, targetJob *batchv1.Job) error {
	return wait.Poll(framework.Poll, cronJobTimeout, func() (bool, error) {
		jobs, err := c.Batch().Jobs(ns).List(metav1.ListOptions{})
		if err != nil {
			return false, err
		}
		_, finishedJobs := filterActiveJobs(jobs)
		for _, job := range finishedJobs {
			if targetJob.Namespace == job.Namespace && targetJob.Name == job.Name {
				return false, nil
			}
		}
		return true, nil
	})
}

// Wait for a job to be replaced with a new one.
func waitForJobReplaced(c clientset.Interface, ns, previousJobName string) error {
	return wait.Poll(framework.Poll, cronJobTimeout, func() (bool, error) {
		jobs, err := c.Batch().Jobs(ns).List(metav1.ListOptions{})
		if err != nil {
			return false, err
		}
		// Ignore Jobs pending deletion, since deletion of Jobs is now asynchronous.
		aliveJobs := filterNotDeletedJobs(jobs)
		if len(aliveJobs) > 1 {
			return false, fmt.Errorf("More than one job is running %+v", jobs.Items)
		} else if len(aliveJobs) == 0 {
			framework.Logf("Warning: Found 0 jobs in namespace %v", ns)
			return false, nil
		}
		return aliveJobs[0].Name != previousJobName, nil
	})
}

// waitForJobsAtLeast waits for at least a number of jobs to appear.
func waitForJobsAtLeast(c clientset.Interface, ns string, atLeast int) error {
	return wait.Poll(framework.Poll, cronJobTimeout, func() (bool, error) {
		jobs, err := c.Batch().Jobs(ns).List(metav1.ListOptions{})
		if err != nil {
			return false, err
		}
		return len(jobs.Items) >= atLeast, nil
	})
}

// waitForAnyFinishedJob waits for any completed job to appear.
func waitForAnyFinishedJob(c clientset.Interface, ns string) error {
	return wait.Poll(framework.Poll, cronJobTimeout, func() (bool, error) {
		jobs, err := c.Batch().Jobs(ns).List(metav1.ListOptions{})
		if err != nil {
			return false, err
		}
		for i := range jobs.Items {
			if job.IsJobFinished(&jobs.Items[i]) {
				return true, nil
			}
		}
		return false, nil
	})
}

// checkNoEventWithReason checks no events with a reason within a list has occured
func checkNoEventWithReason(c clientset.Interface, ns, cronJobName string, reasons []string) error {
	sj, err := c.BatchV1beta1().CronJobs(ns).Get(cronJobName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("Error in getting cronjob %s/%s: %v", ns, cronJobName, err)
	}
	events, err := c.Core().Events(ns).Search(api.Scheme, sj)
	if err != nil {
		return fmt.Errorf("Error in listing events: %s", err)
	}
	for _, e := range events.Items {
		for _, reason := range reasons {
			if e.Reason == reason {
				return fmt.Errorf("Found event with reason %s: %#v", reason, e)
			}
		}
	}
	return nil
}

// filterNotDeletedJobs returns the job list without any jobs that are pending
// deletion.
func filterNotDeletedJobs(jobs *batchv1.JobList) []*batchv1.Job {
	var alive []*batchv1.Job
	for i := range jobs.Items {
		job := &jobs.Items[i]
		if job.DeletionTimestamp == nil {
			alive = append(alive, job)
		}
	}
	return alive
}

func filterActiveJobs(jobs *batchv1.JobList) (active []*batchv1.Job, finished []*batchv1.Job) {
	for i := range jobs.Items {
		j := jobs.Items[i]
		if !job.IsJobFinished(&j) {
			active = append(active, &j)
		} else {
			finished = append(finished, &j)
		}
	}
	return
}
