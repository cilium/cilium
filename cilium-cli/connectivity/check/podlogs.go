// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"bufio"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"

	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/pkg/lock"
)

const logFollowRetryInterval = 5 * time.Second

// LogLine holds a container log line and the time the container runtime got it.
type LogLine struct {
	Time time.Time
	Text string
}

// followedLog holds what the follower read from the log of a container.
type followedLog struct {
	lines []LogLine // the lines it kept
	last  time.Time // the time of the last line it read
}

// logFollower keeps the log lines of the Cilium containers that a check needs.
// The kubelet rotates container logs and the API only serves the current file,
// so a check that reads the logs at the end of a run misses the older lines.
type logFollower struct {
	keep func(line string) bool

	mu   lock.Mutex
	logs map[string]*followedLog // by container ID
}

// FollowCiliumLogs keeps the Cilium pod log lines for which keep returns true
// until ctx ends. It does nothing when the user filtered out the scenario, and
// skips the clusters whose agents do not log at debug level.
func (ct *ConnectivityTest) FollowCiliumLogs(ctx context.Context, scenario string, keep func(line string) bool) {
	if !ct.params.testEnabled(scenario) {
		return
	}

	f := &logFollower{keep: keep, logs: make(map[string]*followedLog)}
	for _, client := range ct.Clients() {
		// Without debug logging, an agent takes hours to fill a kubelet log file.
		cm, err := client.GetConfigMap(ctx, ct.params.CiliumNamespace, defaults.ConfigMapName, metav1.GetOptions{})
		if err != nil || cm.Data["debug"] != "true" {
			continue
		}

		// A clientset of its own keeps the log streams off the rate limiter of the tests.
		clientset, err := kubernetes.NewForConfig(rest.CopyConfig(client.Config))
		if err != nil {
			ct.Warnf("Unable to follow the Cilium pod logs: %s", err)
			continue
		}
		pods := clientset.CoreV1().Pods(ct.params.CiliumNamespace)
		list, err := pods.List(ctx, metav1.ListOptions{LabelSelector: ct.params.CiliumPodSelector})
		if err != nil {
			ct.Warnf("Unable to list the Cilium pods to follow their logs: %s", err)
			continue
		}
		for _, pod := range list.Items {
			for _, status := range pod.Status.ContainerStatuses {
				if status.State.Running != nil {
					go f.follow(ctx, pods, pod.Name, status.Name, status.ContainerID)
				}
			}
		}
	}
	ct.logFollower = f
}

// FollowedLog returns the kept lines of a container, oldest first, and the time
// of the last line the follower read from it, or zero if it read none.
func (ct *ConnectivityTest) FollowedLog(containerID string) ([]LogLine, time.Time) {
	if ct.logFollower == nil || containerID == "" {
		return nil, time.Time{}
	}
	ct.logFollower.mu.Lock()
	defer ct.logFollower.mu.Unlock()
	l, ok := ct.logFollower.logs[containerID]
	if !ok {
		return nil, time.Time{}
	}
	return slices.Clone(l.lines), l.last
}

// follow streams the log of a container. When the stream ends, it resumes
// after the last line, or from the start of the container that replaced it.
func (f *logFollower) follow(ctx context.Context, pods typedcorev1.PodInterface, pod, container, containerID string) {
	var last time.Time
	for {
		opts := &corev1.PodLogOptions{Container: container, Follow: true, Timestamps: true}
		if !last.IsZero() {
			opts.SinceTime = &metav1.Time{Time: last}
		}
		stream, err := pods.GetLogs(pod, opts).Stream(ctx)
		if err == nil {
			last, err = f.read(containerID, stream, last)
			stream.Close()
			// Resume a dropped stream at once, before a rotation can take lines away.
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				continue
			}
		}

		id, err := waitForContainer(ctx, pods, pod, container)
		if err != nil {
			return
		}
		if id != containerID {
			containerID, last = id, time.Time{}
		}
	}
}

// read keeps the complete lines of a log stream that come after resume, and
// records the time of the last one. It returns that time and the error that
// ended the stream.
func (f *logFollower) read(containerID string, r io.Reader, resume time.Time) (time.Time, error) {
	last := resume
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return last, err
		}
		ts, text, ok := strings.Cut(strings.TrimSuffix(line, "\n"), " ")
		if !ok {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil || !t.After(resume) {
			continue
		}
		last = t
		kept := f.keep(text)
		f.mu.Lock()
		l, ok := f.logs[containerID]
		if !ok {
			l = &followedLog{}
			f.logs[containerID] = l
		}
		l.last = t
		if kept {
			l.lines = append(l.lines, LogLine{Time: t, Text: text})
		}
		f.mu.Unlock()
	}
}

// waitForContainer waits until a container of the pod runs and returns its ID.
// It fails once ctx ends or the pod disappears.
func waitForContainer(ctx context.Context, pods typedcorev1.PodInterface, pod, container string) (string, error) {
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(logFollowRetryInterval):
		}

		p, err := pods.Get(ctx, pod, metav1.GetOptions{})
		if k8serrors.IsNotFound(err) {
			return "", err
		}
		if err != nil {
			continue
		}
		for _, status := range p.Status.ContainerStatuses {
			if status.Name == container && status.State.Running != nil {
				return status.ContainerID, nil
			}
		}
	}
}
