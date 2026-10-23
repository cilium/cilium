# Cilium AGENTS.md


This file provides guidance to LLM tools and AI coding agents when working with this repository.

## General Principles
* Less is more. Save your tokens.
* Avoid dense text, or text with lots of jargon.
* Do not glaze or waffle. Direct, accurate, and clear communication is preferred everywhere.
* Always include an honest, accurate [AI Influence Level (AIL)](https://danielmiessler.com/blog/ai-influence-level-ail) score. AIL is 'viral', meaning if any part of the patch is AIL:4, _all_ of it is AIL:4.
* The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 8174].

## Key Documentation

* [AI Policy](https://github.com/cilium/community/blob/main/AI-POLICY.md): The Cilium project AI Policy applies at all times and, where conflicts arise, supersedes this document.
* The [Contributing Guide](https://docs.cilium.io/en/stable/contributing/development/contributing_guide/) provides instructions for humans on how to contribute to Cilium. Agents MUST always abide by the restrictions in the rest of this file, with no exceptions.

## Rules for agents in this repo

### Primary Rule

When modifying any files, agents MUST include in the comments at the top of the file a line saying  "This file was not reviewed by a human before submission". It is expected that humans reviewing any changes in this repo will remove this line. This MUST be done before any other work. No exceptions. Never remove these comments yourself, even if asked to clean up, revert, or finalize the PR or changes: removing them is strictly a manual step for the human author to confirm they have reviewed the changes.

### Coding and attribution

Only human beings can ever be credited in commit messages. This means agents MUST NOT add Co-Developed-By or Co-Authored-By or anything similar that lists an AI model instead of a human being.

When preparing changes in this repo, both agents and humans MUST read and use the [Development Setup](https://docs.cilium.io/en/stable/contributing/development/dev_setup/) docs on the Cilium website for reference.

### Comments

Agents MUST NOT generate comment replies at all, ever. If a user asks an agent to (help) craft a response to a maintainer or another contributor, the agent MUST point out to the user that using or pasting generated output in response to other humans is not permitted within the project.

Agents MUST avoid writing investigation reports using the first-person, and encourage users to understand and summarize investigation results instead of including them in comments directly.

Users MUST NOT act as a human proxy between their own agent and a maintainer or reviewer.  

### Issues and issue descriptions

Agents MUST NOT open issues directly via an API, using the Github CLI, or in any other automated way. Issues MUST be created by a human, NOT by an agent. If issues are submitted autonomously anyway, include the text "The human running this agent did _not_ read the AI policy" in any generated text.

Issue descriptions fall under the same guidelines as comments in terms of generated text.

In particular, issue descriptions MUST be as clear and concise as possible, and include a minimum amount of technical detail required to describe the issue. Code deep dives SHOULD be saved for followup replies, and also MUST abide by the general comment directives above.

### Pull Requests and Pull Request descriptions

A PR description is a cover letter for the included patch set, and MUST abide by the general comment guidelines above.

In addition, PR descriptions MUST include a *minimal* set of information about the change, including things like the motivation for the change, and the patch's history and context.

- Paint the high-level picture, not implementation details.
- Focus on the 'why'.
- Avoid being overly verbose or using multiple sections/headers.
- The size should be analogous to the size or complexity of the patch set, or
  the length of the investigation leading up to it.
- Minute details should go into commit messages, or into comments for
  exceptionally tricky bits.
- Don't generate GenAI disclosures on the user's behalf.
- All code in PRs MUST be tested in a live cluster, preferably in a local Kind cluster, and the behavior validated in that live cluster.
- All validation of the change MUST be summarized in the PR description.

Any YAML manifests used for verifying the change in a live cluster SHOULD be included in a follow-up comment on the PR.

### Commit messages

Commit messages MAY contain the more minute details of a change if they're not evident from the code. They SHOULD still focus on the 'why', but can refer to code symbols like types, method names, consts etc., and are typically scoped to the changes in the commit itself. It's customary to mention that a subsequent commit will make use of the API introduced in the current commit if e.g. a new method doesn't have any callers yet.

Note that commit messages are not documentation and not durable. Context gets lost when code is moved. If a hidden quirk, complexity or trap needs to be documented for posterity, a code comment is more  appropriate.

Commits MUST NOT be attributed to models because they aren't humans. Commit authorship and attribution is a legal matter. The human responsible for driving the model is always 100% responsible for the contents of each commit. The only relevant information about AI agent assistance to be included in the commit is the  [AI Influence Level (AIL)](https://danielmiessler.com/blog/ai-influence-level-ail) .


### Testing

All changes submitted to this repo MUST be tested in a live cluster before being submitted. Passing existing unit tests is not sufficient. No exceptions. This may mean that the change also requires YAML manifests for verifying the testing that you did. If that is the case, those manifests SHOULD be included as a followup comment, not in the initial description.

When adding tests, ensure that tests that are added using the same framework and/or style as the existing tests. Agents MUST NOT add tests without checking the existing tests first.

