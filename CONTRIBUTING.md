# Contributing to DockerShield

First off, thanks for taking the time to contribute! 🎉

The following is a set of guidelines for contributing to DockerShield. These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Features](#suggesting-features)
  - [Your First Code Contribution](#your-first-code-contribution)
  - [Pull Requests](#pull-requests)
- [Development Setup](#development-setup)
- [Coding Style](#coding-style)
- [Testing](#testing)
- [Commit Messages](#commit-messages)

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When you create a bug report, include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps to reproduce the problem**
- **Provide specific examples** (commands you ran, expected vs actual output)
- **Include system information** (OS, Docker version, DockerShield version)
- **Add logs or screenshots** if applicable

### Suggesting Features

Feature requests are welcome! Before creating a feature request:

- **Check if the feature has already been requested**
- **Provide a clear use case** - why would this be useful?
- **Describe the expected behavior**
- **Consider implementation complexity** - is this feasible?

### Your First Code Contribution

Unsure where to begin? Look for issues labeled:

- `good-first-issue` - Simple changes, great for newcomers
- `help-wanted` - More complex issues where we need community help
- `documentation` - Documentation improvements

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** with clear, focused commits
3. **Add tests** if you're adding functionality
4. **Update documentation** if you're changing behavior
5. **Ensure all tests pass** (`make test`)
6. **Format your code** (`make fmt`)
7. **Submit your pull request**

**PR Requirements:**
- Clear title describing the change
- Description explaining what and why
- Reference any related issues (`Fixes #123`)
- All CI checks must pass
- At least one maintainer approval required

## Development Setup

### Prerequisites

- Go 1.21 or higher
- Docker Engine running
- Make (for build commands)
- Git

### Clone and Build

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/dockershield.git
cd dockershield

# Add upstream remote
git remote add upstream https://github.com/adrian13508/dockershield.git

# Install dependencies
go mod download

# Build the project
make build

# Run tests
make test

# Format code
make fmt

# Run linters
go vet ./...
```

### Running Locally

```bash
# Build and run
./dockershield scan

# Run with verbose output
./dockershield scan --verbose

# Test JSON output
./dockershield scan --json
```

### Project Structure

```
dockershield/
├── cmd/dockershield/       # Main application entry point
├── internal/
│   ├── docker/            # Docker API client and scanning
│   ├── analyzer/          # Port risk analysis and scoring
│   ├── security/          # System security checks (SSH, fail2ban, updates)
│   ├── system/            # Firewall/iptables monitoring
│   ├── reporter/          # Report generation (terminal, JSON)
│   └── updater/           # Auto-update functionality
├── pkg/models/            # Shared data types and models
├── .github/               # GitHub workflows and templates
└── Makefile               # Build and development commands
```

## Coding Style

We follow standard Go conventions:

### General Guidelines

- **Follow Go idioms** - When in doubt, refer to [Effective Go](https://golang.org/doc/effective_go)
- **Keep functions small** - Each function should do one thing well
- **Write clear variable names** - Prefer `containerName` over `cn`
- **Add comments for complex logic** - Explain the "why", not the "what"
- **Handle errors explicitly** - No silent failures

### Code Formatting

```bash
# Format all code (required before committing)
go fmt ./...
make fmt

# Run linters
go vet ./...
```

### Example Code Style

```go
// Good: Clear function name, explicit error handling
func GetContainerPorts(containerID string) ([]Port, error) {
    if containerID == "" {
        return nil, fmt.Errorf("container ID cannot be empty")
    }

    // Use Docker API to inspect container
    container, err := client.ContainerInspect(ctx, containerID)
    if err != nil {
        return nil, fmt.Errorf("failed to inspect container: %w", err)
    }

    return extractPorts(container), nil
}

// Bad: Unclear name, ignores errors
func GetPorts(id string) []Port {
    c, _ := client.ContainerInspect(ctx, id)
    return extractPorts(c)
}
```

## Testing

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
go test -v -cover ./...

# Run specific package tests
go test -v ./internal/analyzer/

# Run tests with race detection
go test -race ./...
```

### Writing Tests

- **Test file naming**: `foo.go` → `foo_test.go`
- **Test function naming**: `TestFunctionName` or `TestFunctionName_Scenario`
- **Use table-driven tests** for multiple test cases
- **Mock external dependencies** (Docker API, file system)

Example test:

```go
func TestAnalyzePortRisk(t *testing.T) {
    tests := []struct {
        name     string
        port     Port
        expected RiskLevel
    }{
        {
            name:     "public PostgreSQL is critical",
            port:     Port{HostIP: "0.0.0.0", HostPort: "5432"},
            expected: RiskCritical,
        },
        {
            name:     "localhost PostgreSQL is low",
            port:     Port{HostIP: "127.0.0.1", HostPort: "5432"},
            expected: RiskLow,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := AnalyzePortRisk(tt.port)
            if result != tt.expected {
                t.Errorf("expected %v, got %v", tt.expected, result)
            }
        })
    }
}
```

## Commit Messages

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification.

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `refactor:` Code refactoring (no functional changes)
- `test:` Adding or updating tests
- `chore:` Maintenance tasks (dependencies, build config)
- `perf:` Performance improvements
- `ci:` CI/CD changes

### Examples

```bash
# Good commit messages
git commit -m "feat(docker): add support for Docker Compose networks"
git commit -m "fix(analyzer): handle containers without exposed ports"
git commit -m "docs(readme): add installation troubleshooting section"

# With body and footer
git commit -m "fix(updater): prevent nil pointer dereference for private repos

The updater crashed when checking for updates in private repositories
because it tried to access repository metadata that wasn't available.

Added nil checks and graceful fallback to local version.

Fixes #42"
```

## Getting Help

- **Questions?** Open a [discussion](https://github.com/adrian13508/dockershield/discussions)
- **Found a bug?** Open an [issue](https://github.com/adrian13508/dockershield/issues)
- **Need clarification?** Comment on the relevant issue or PR

## Recognition

Contributors will be:
- Listed in release notes
- Mentioned in the README (for significant contributions)
- Given credit in commit messages (Co-authored-by)

Thank you for contributing to DockerShield! 🛡️

---

**Note:** This is a young project and these guidelines may evolve. Suggestions for improving this document are welcome!
