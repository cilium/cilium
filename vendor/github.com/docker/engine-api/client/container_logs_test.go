package client

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/docker/engine-api/types"

	"golang.org/x/net/context"
)

func TestContainerLogsError(t *testing.T) {
	client := &Client{
		transport: newMockClient(nil, errorMock(http.StatusInternalServerError, "Server error")),
	}
	_, err := client.ContainerLogs(context.Background(), "container_id", types.ContainerLogsOptions{})
	if err == nil || err.Error() != "Error response from daemon: Server error" {
		t.Fatalf("expected a Server Error, got %v", err)
	}
	_, err = client.ContainerLogs(context.Background(), "container_id", types.ContainerLogsOptions{
		Since: "2006-01-02TZ",
	})
	if err == nil || !strings.Contains(err.Error(), `parsing time "2006-01-02TZ"`) {
		t.Fatalf("expected a 'parsing time' error, got %v", err)
	}
}

func TestContainerLogs(t *testing.T) {
	expectedURL := "/containers/container_id/logs"
	cases := []struct {
		options             types.ContainerLogsOptions
		expectedQueryParams map[string]string
	}{
		{
			expectedQueryParams: map[string]string{
				"tail": "",
			},
		},
		{
			options: types.ContainerLogsOptions{
				Tail: "any",
			},
			expectedQueryParams: map[string]string{
				"tail": "any",
			},
		},
		{
			options: types.ContainerLogsOptions{
				ShowStdout: true,
				ShowStderr: true,
				Timestamps: true,
				Details:    true,
				Follow:     true,
			},
			expectedQueryParams: map[string]string{
				"tail":       "",
				"stdout":     "1",
				"stderr":     "1",
				"timestamps": "1",
				"details":    "1",
				"follow":     "1",
			},
		},
		{
			options: types.ContainerLogsOptions{
				// An complete invalid date, timestamp or go duration will be
				// passed as is
				Since: "invalid but valid",
			},
			expectedQueryParams: map[string]string{
				"tail":  "",
				"since": "invalid but valid",
			},
		},
	}
	for _, logCase := range cases {
		client := &Client{
			transport: newMockClient(nil, func(r *http.Request) (*http.Response, error) {
				if !strings.HasPrefix(r.URL.Path, expectedURL) {
					return nil, fmt.Errorf("Expected URL '%s', got '%s'", expectedURL, r.URL)
				}
				// Check query parameters
				query := r.URL.Query()
				for key, expected := range logCase.expectedQueryParams {
					actual := query.Get(key)
					if actual != expected {
						return nil, fmt.Errorf("%s not set in URL query properly. Expected '%s', got %s", key, expected, actual)
					}
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte("response"))),
				}, nil
			}),
		}
		body, err := client.ContainerLogs(context.Background(), "container_id", logCase.options)
		if err != nil {
			t.Fatal(err)
		}
		defer body.Close()
		content, err := ioutil.ReadAll(body)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != "response" {
			t.Fatalf("expected response to contain 'response', got %s", string(content))
		}
	}
}

func ExampleClient_ContainerLogs_withTimeout() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, _ := NewEnvClient()
	reader, err := client.ContainerLogs(ctx, "container_id", types.ContainerLogsOptions{})
	if err != nil {
		log.Fatal(err)
	}

	_, err = io.Copy(os.Stdout, reader)
	if err != nil && err != io.EOF {
		log.Fatal(err)
	}
}
