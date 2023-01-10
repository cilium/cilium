// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probe

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// http Client for probing
// Use our custom client since DefaultClient specifies timeout of 0 (no timeout).
// See https://medium.com/@nate510/don-t-use-go-s-default-http-client-4804cb19f779.
// Use a timeout of 30s.
var client = &http.Client{Timeout: 30 * time.Second}

// GetHello performs a GET request on the /hello endpoint
func GetHello(host string) error {
	hostURL, err := url.Parse(host)
	if err != nil {
		return err
	}

	requestURL, err := hostURL.Parse("/hello")
	if err != nil {
		return err
	}

	resp, err := client.Get(requestURL.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d %s", resp.StatusCode, resp.Status)
	}

	return nil
}
