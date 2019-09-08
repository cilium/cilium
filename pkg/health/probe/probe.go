// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
