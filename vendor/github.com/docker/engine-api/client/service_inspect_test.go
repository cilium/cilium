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

func TestServiceInspectError(t *testing.T) {
	client := &Client{
		transport: newMockClient(nil, errorMock(http.StatusInternalServerError, "Server error")),
	}

	_, _, err := client.ServiceInspectWithRaw(context.Background(), "nothing")
	if err == nil || err.Error() != "Error response from daemon: Server error" {
		t.Fatalf("expected a Server Error, got %v", err)
	}
}

func TestServiceInspectServiceNotFound(t *testing.T) {
	client := &Client{
		transport: newMockClient(nil, errorMock(http.StatusNotFound, "Server error")),
	}

	_, _, err := client.ServiceInspectWithRaw(context.Background(), "unknown")
	if err == nil || !IsErrServiceNotFound(err) {
		t.Fatalf("expected an serviceNotFoundError error, got %v", err)
	}
}

func TestServiceInspect(t *testing.T) {
	expectedURL := "/services/service_id"
	client := &Client{
		transport: newMockClient(nil, func(req *http.Request) (*http.Response, error) {
			if !strings.HasPrefix(req.URL.Path, expectedURL) {
				return nil, fmt.Errorf("Expected URL '%s', got '%s'", expectedURL, req.URL)
			}
			content, err := json.Marshal(swarm.Service{
				ID: "service_id",
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

	serviceInspect, _, err := client.ServiceInspectWithRaw(context.Background(), "service_id")
	if err != nil {
		t.Fatal(err)
	}
	if serviceInspect.ID != "service_id" {
		t.Fatalf("expected `service_id`, got %s", serviceInspect.ID)
	}
}
