# Contributing to Kitch

Thank you for your interest in contributing to Kitch! We welcome all kinds of contributions, including bug reports, feature requests, documentation improvements, and code.

## How to Contribute

### 1. Fork the Repository
- Click the "Fork" button at the top right of this repository.
- Clone your fork to your local machine:
  ```sh
  git clone https://github.com/King-kin5/kitch.git
  cd kitch
  ```

### 2. Create a Branch
- Create a new branch for your feature or bugfix:
  ```sh
  git checkout -b feature/your-feature-name
  ```

### 3. Make Your Changes
- Write clear, concise, and well-documented code.
- Follow the existing code style and structure.
- Add or update tests as appropriate.
- Run tests and linters before submitting:
  ```sh
  go test ./...
  golangci-lint run
  ```

### 4. Commit and Push
- Commit your changes with a descriptive message:
  ```sh
  git add .
  git commit -m "Add feature: your feature description"
  git push origin feature/your-feature-name
  ```

### 5. Open a Pull Request
- Go to your fork on GitHub and click "Compare & pull request".
- Fill out the PR template and describe your changes.
- Reference any related issues (e.g., "Closes #42").

### 6. Code Review
- Be responsive to feedback and suggestions from maintainers.
- Make any requested changes and update your PR.

## Code Style
- Use idiomatic Go (see [Effective Go](https://golang.org/doc/effective_go.html)).
- Use `gofmt` and `golangci-lint` to format and lint your code.
- Write clear comments and documentation for exported functions and types.
- Keep functions small and focused.

## Issue Reporting
- Search existing issues before opening a new one.
- Provide as much detail as possible (steps to reproduce, logs, screenshots).
- Use clear and descriptive titles.

## Feature Requests
- Explain your use case and why the feature is needed.
- Propose a possible implementation if you have one in mind.

## Community Standards
- Be respectful and inclusive.
- Follow the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/0/code_of_conduct/).



---

Thank you for helping make Kitch better! 