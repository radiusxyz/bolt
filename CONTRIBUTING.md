# Contributing to Bolt

Thank you for your interest in contributing to Bolt! 

We welcome contributions at all levels. Whether you’re a beginner or an experienced developer, your input is valued. This guide will help you get started.

If you have questions or need help, feel free to reach out to the team on [Discord](https://discord.com/invite/Q8xAsuCVrT).

---

## Code of Conduct

Bolt adheres to the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct). Please ensure your interactions are respectful and constructive.  

Violations of the Code of Conduct can be reported by contacting the team.

---

## Ways to Contribute

There are several ways you can contribute:

1. **Report an Issue**  
   If you’ve found a bug or have feedback, open an issue in the issue tracker. Be sure to include relevant details like your environment and steps to reproduce the issue.

2. **Contribute Code**  
   Fix bugs, improve performance, or add new features by submitting a pull request.

3. **Resolving Issues**  
   If you're interested in resolving an issue, please comment on the issue to let us know you want to work on it and outline a plan for tackling it. A good place to start looking for work is issues labeled with [good first issue](https://github.com/chainbound/bolt/issues?q=is%3Aissue%20state%3Aopen%20label%3AD-good-first-issue).

---

### Exclusions  

We do not accept contributions focused solely on fixing typos or minor grammatical errors in documentation or code comments.

---

## Submitting Pull Requests  

Before submitting a pull request:  
- Make sure your changes are logically grouped and adhere to Rust standards (e.g., run `just fmt` and `just clippy`).
- Include tests for any new functionality or bug fixes.
- Consider opening a draft pull request if your work is ongoing or you’d like early feedback.
- Consider [running the devnet locally](README.md#running-the-devnet) when testing.
- We use [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) for commit messages.

---

## Adding Tests  

If your changes include code updates, ensure they are properly tested:  
- **Unit Tests:** For individual functions or components.  
- **Integration Tests:** For larger, cross-functional features.  

Run `just test` locally to confirm all tests pass.

---

By contributing to Bolt, you agree to license your contributions under MIT license.

Thank you for helping make Bolt better!
