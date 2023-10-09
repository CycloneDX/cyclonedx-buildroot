# Contributing

Welcome, and thank you for your interest in contributing to the CycloneDX project.

## Asking Questions

Have a question? Rather than opening an issue, ask away on Stack Overflow.

A well worded question will help serve as a resource to others searching for help.

And answering questions on Stack Overflow is a great way to contribute to CycloneDX without writing code.

## Look For An Existing Issue

Before you create a new issue, please do a search in open issues to see if the issue or feature request has already been filed.

If you find your issue already exists, add relevant comments to the existing issue.

If you cannot find an existing issue for your bug or feature request create a new issue using the guidelines below.

## Writing Good Bug Reports

File a single issue per bug. Do not list multiple bugs in the same issue.

The more information you can provide, the more likely we will be successful at reproducing the bug and finding a fix.

Please include the following with each bug report:
- the version you are using
- your operating system and version
- reproducible steps (1 2 3...) that cause the issue including any required files
- what you expected, versus what happened
- any relevant screenshots and other outputs

## Feature Requests

File a single issue per feature request. Do not list multiple feature requests in the same issue.

Describe your use case and the value you will get from the requested feature.

## Contributing Code and Pull Requests

- Pull requests that do not merge easily with the tip of the master branch will be declined. The author will be asked to merge with tip and submit a new pull request.
- Code should follow standard code style conventions for whitespace, indentation and naming. In the case of style differences between existing code and language standards, consistency with existing code is preferred.
- New functionality should have corresponding tests added to the existing test suite if possible.
- Avoid new dependencies if the functionality that is being used is trivial to implement directly or is available in standard libraries.
- Avoid checking in unrelated whitespace changes with code changes. They add noise to your pull request making it harder to review.

Please follow these rules when writing a commit message:
- Separate subject from body with a blank line
- Limit the subject line to 50 characters
- Capitalize the subject line
- Do not end the subject line with a period
- Use the imperative mood in the subject line
- Wrap the body at 72 characters
- Use the body to explain what and why vs. how
- Commits must be signed off to indicate agreement with [Developer Certificate of Origin (DCO)](https://developercertificate.org/).  
  To sign-off include `Signed-off-by: Author Name <authoremail@example.com>` in every commit message.  
  You can do this automatically by using git's `-s` flag (i.e., `git commit -s`).

[How to Write a Git Commit Message](https://chris.beams.io/posts/git-commit/) is a greate guide to writing good commit messages.
