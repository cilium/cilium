// Copyright 2026 The go-github AUTHORS. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package github

// AgentsService handles communication with the Agents related
// methods of the GitHub API.
//
// The Agents endpoints are only served by the 2026-03-10 API version, so these
// methods send that version explicitly instead of the client's default.
//
// GitHub API docs: https://docs.github.com/rest/agents?apiVersion=2026-03-10
type AgentsService service
