// Copyright 2017 Google Inc.
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

package licenseclassifier

import "regexp"

var (
	reCCBYNC   = regexp.MustCompile(`(?i).*\bAttribution NonCommercial\b.*`)
	reCCBYNCND = regexp.MustCompile(`(?i).*\bAttribution NonCommercial NoDerivs\b.*`)
	reCCBYNCSA = regexp.MustCompile(`(?i).*\bAttribution NonCommercial ShareAlike\b.*`)

	// forbiddenRegexps are regular expressions we expect to find in
	// forbidden licenses. If we think we have a forbidden license but
	// don't find the equivalent phrase, then it's probably just a
	// misclassification.
	forbiddenRegexps = map[string]*regexp.Regexp{
		AGPL10:     regexp.MustCompile(`(?i).*\bAFFERO GENERAL PUBLIC LICENSE\b.*`),
		AGPL30:     regexp.MustCompile(`(?i).*\bGNU AFFERO GENERAL PUBLIC LICENSE\b.*`),
		CCBYNC10:   reCCBYNC,
		CCBYNC20:   reCCBYNC,
		CCBYNC25:   reCCBYNC,
		CCBYNC30:   reCCBYNC,
		CCBYNC40:   reCCBYNC,
		CCBYNCND10: regexp.MustCompile(`(?i).*\bAttribution NoDerivs NonCommercial\b.*`),
		CCBYNCND20: reCCBYNCND,
		CCBYNCND25: reCCBYNCND,
		CCBYNCND30: reCCBYNCND,
		CCBYNCND40: regexp.MustCompile(`(?i).*\bAttribution NonCommercial NoDerivatives\b.*`),
		CCBYNCSA10: reCCBYNCSA,
		CCBYNCSA20: reCCBYNCSA,
		CCBYNCSA25: reCCBYNCSA,
		CCBYNCSA30: reCCBYNCSA,
		CCBYNCSA40: reCCBYNCSA,
		WTFPL:      regexp.MustCompile(`(?i).*\bDO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE\b.*`),
	}
)
