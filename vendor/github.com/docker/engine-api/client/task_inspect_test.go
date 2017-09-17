package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/docker/engine-api/types/swarm"
	"golang.org/x/net/context"
)

func TestTaskInspectError(t *testing.T) {
	client := &Client{
		transport: newMockClient(nil, errorMock(http.StatusInternalServerError, "Server error")),
	}

	_, _, err := client.TaskInspectWithRaw(context.Background(), "nothing")
	if err == nil || err.Error() != "Error response from daemon: Server error" {
		t.Fatalf("expected a Server Error, got %v", err)
	}
}

func TestTaskInspect(t *testing.T) {
	expectedURL := "/tasks/task_id"
	client := &Client{
		transport: newMockClient(nil, func(req *http.Request) (*http.Response, error) {
			if !strings.HasPrefix(req.URL.Path, expectedURL) {
				return nil, fmt.Errorf("Expected URL '%s', got '%s'", expectedURL, req.URL)
			}
			content, err := json.Marshal(swarm.Task{
				ID: "task_id",
			})
			if err != nil {
				return nil, err
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       ioutil.NopCloser(bytes.NewReader(content)),
			}, nil
		}),
	}

	taskInspect, _, err := client.TaskInspectWithRaw(context.Background(), "task_id")
	if err != nil {
		t.Fatal(err)
	}
	if taskInspect.ID != "task_id" {
		t.Fatalf("expected `task_id`, got %s", taskInspect.ID)
	}
}
