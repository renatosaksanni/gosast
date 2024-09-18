# gosast

**gosast** is a custom **Static Application Security Testing (SAST)** linter for **Golang** projects. It is designed to identify and report security vulnerabilities in your Go codebase, ensuring adherence to best practices and compliance with security standards such as **OWASP Top Ten** and **CWE (Common Weakness Enumeration)**.

## Table of Contents

- [Supported Vulnerabilities](#supported-vulnerabilities)
  - [OWASP Top Ten](#owasp-top-ten)
  - [CWE Categories](#cwe-categories)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Integration with GitLab CI/CD](#integration-with-gitlab-cicd)
- [Contributing](#contributing)
- [License](#license)

## Supported Vulnerabilities

**gosast** covers a broad spectrum of security vulnerabilities categorized under **OWASP Top Ten** and **CWE**. Below is a detailed list of the vulnerabilities detected by each rule, along with their corresponding OWASP and CWE references.

### OWASP Top Ten

| Rule                        | OWASP Top Ten Category   | Description                                                                 |
|-----------------------------|--------------------------|-----------------------------------------------------------------------------|
| **SQL Injection**           | A1: Injection            | Detects potential SQL injection vulnerabilities where user input is unsafely included in SQL queries. |
| **Command Injection**       | A1: Injection            | Identifies instances where user input is used to execute system commands without proper validation. |
| **Cross-Site Scripting (XSS)** | A7: Cross-Site Scripting | Detects vulnerabilities where untrusted data is included in web pages without proper sanitization. |
| **Weak Authentication**     | A2: Broken Authentication | Identifies insecure password hashing mechanisms, ensuring that strong algorithms like bcrypt are used. |
| **Sensitive Data Exposure** | A3: Sensitive Data Exposure | Detects instances where sensitive information (e.g., passwords) is logged or exposed without encryption. |
| **XML External Entities (XXE)** | A4: XML External Entities | Identifies vulnerabilities related to the processing of XML input containing external entity references. |
| **Broken Access Control**   | A5: Broken Access Control | Detects missing authorization checks in HTTP handlers, ensuring that access controls are properly enforced. |
| **Security Misconfiguration** | A6: Security Misconfiguration | Identifies insecure configurations, such as debug modes or improper middleware usage. |
| **Insecure Deserialization** | A8: Insecure Deserialization | Detects vulnerabilities related to deserializing untrusted data without validation. |
| **Using Components with Known Vulnerabilities** | A9: Using Components with Known Vulnerabilities | Identifies outdated dependencies that may contain known security flaws. |
| **Insufficient Logging & Monitoring** | A10: Insufficient Logging & Monitoring | Detects missing logging statements for critical operations, ensuring that security-relevant events are recorded. |

### CWE Categories

| Rule                        | CWE Category                     | Description                                                                 |
|-----------------------------|----------------------------------|-----------------------------------------------------------------------------|
| **SQL Injection**           | CWE-89: SQL Injection            | Exploitation of a vulnerability in the software by injecting malicious SQL statements. |
| **Command Injection**       | CWE-77: Command Injection        | Execution of arbitrary commands on the host operating system via a vulnerable application. |
| **Cross-Site Scripting (XSS)** | CWE-79: Improper Neutralization of Input During Web Page Generation | Injection of malicious scripts into web pages viewed by other users.        |
| **Weak Authentication**     | CWE-307: Improper Restriction of Excessive Authentication Attempts | Inadequate mechanisms to protect against brute force or weak authentication methods. |
| **Sensitive Data Exposure** | CWE-200: Information Exposure    | Unintended exposure of sensitive information to unauthorized actors.         |
| **XML External Entities (XXE)** | CWE-611: Improper Restriction of XML External Entity Reference | Processing of XML input containing external entity references leading to information disclosure. |
| **Broken Access Control**   | CWE-284: Improper Access Control | Inadequate enforcement of access restrictions, allowing unauthorized actions. |
| **Security Misconfiguration** | CWE-16: Configuration                 | Incorrect or insecure configuration of software or systems.                  |
| **Insecure Deserialization** | CWE-502: Deserialization of Untrusted Data | Deserialization of untrusted data leading to remote code execution or other attacks. |
| **Using Components with Known Vulnerabilities** | CWE-937: Use of Untrusted Components in a Security Decision | Incorporating third-party components that have known security vulnerabilities. |
| **Insufficient Logging & Monitoring** | CWE-778: Insufficient Logging | Lack of adequate logging mechanisms to detect and respond to security incidents. |
| **Path Traversal**          | CWE-22: Improper Limitation of a Pathname to a Restricted Directory | Manipulation of file paths to access unauthorized directories or files.       |
| **Error Handling**          | CWE-703: Improper Handling of Exceptional Conditions | Inadequate error handling that may expose sensitive information or allow exploitation. |

## Installation

### Prerequisites

- **Go**: Version 1.20 or higher
- **Docker**: Optional, for containerized environments
- **GitLab**: For CI/CD integration

### Clone the Repository

```bash
git clone https://github.com/renatosaksanni/gosast.git
cd gosast
```

### Build the Binary

```bash
go build -o gosast ./cmd/gosast
```

### Build the Docker Image (Optional)

```bash
docker build -t your-repo/gosast:v1.0.0 .
```

## Usage

Run the linter against your Go project:

```bash
./gosast --config ./config/.gosast.yml --format json --output sast-report.json
```

### Command-Line Flags

- `--config`: Path to the configuration file (default: `./config/.gosast.yml`)
- `--format`: Output format (`json` or `xml`) (default: `json`)
- `--output`: Output report file path (default: `sast-report.json`)

### Example

```bash
./gosast --config ./config/.gosast.yml --format xml --output sast-report.xml
```

## Configuration

The configuration file **`.gosast.yml`** allows you to enable or disable specific rules and define severity levels.

```yaml
# config/.gosast.yml

linters:
  gosec:
    enabled: true
  staticcheck:
    enabled: true
  custom:
    enabled: true
    rules:
      - sql_injection
      - command_injection
      - xss
      - weak_authentication
      - sensitive_data_exposure
      - xxe
      - broken_access_control
      - security_misconfiguration
      - insecure_deserialization
      - dependency_vulnerabilities
      - logging
      - resource_management
      - input_validation
      - path_traversal
      - error_handling

severity_levels:
  critical:
    - sql_injection
    - command_injection
    - weak_authentication
    - cryptography
  high:
    - xss
    - sensitive_data_exposure
    - broken_access_control
    - security_misconfiguration
    - path_traversal
  medium:
    - insecure_deserialization
    - dependency_vulnerabilities
    - logging
    - resource_management
  low:
    - input_validation
    - error_handling
```

### Customizing Rules

To enable or disable specific rules, modify the `rules` list under the `custom` section. For example, to disable `xss` and `path_traversal`:

```yaml
custom:
  enabled: true
  rules:
    - sql_injection
    - command_injection
    - weak_authentication
    - sensitive_data_exposure
    - xxe
    - broken_access_control
    - security_misconfiguration
    - insecure_deserialization
    - dependency_vulnerabilities
    - logging
    - resource_management
    - input_validation
    - error_handling
```

## Integration with GitLab CI/CD

To automate security checks, integrate **gosast** into your GitLab CI/CD pipeline. Below is an example `.gitlab-ci.yml` configuration:

```yaml
# .gitlab-ci.yml

stages:
  - build
  - test
  - lint
  - security
  - deploy

variables:
  GOSAST_VERSION: v1.0.0

# Build Stage
build:
  stage: build
  image: golang:1.20-alpine
  script:
    - go build -o gosast ./cmd/gosast
  artifacts:
    paths:
      - gosast
  only:
    - branches

# Test Stage
test:
  stage: test
  image: golang:1.20-alpine
  script:
    - go test ./...
  only:
    - branches

# Security Analysis Stage
gosast_linter:
  stage: security
  image: your-repo/gosast:${GOSAST_VERSION}
  script:
    - ./gosast --config ./config/.gosast.yml --format json --output sast-report.json
  artifacts:
    reports:
      sast: sast-report.json
    paths:
      - sast-report.json
  allow_failure: false
  only:
    - branches

# Deployment Stage
deploy:
  stage: deploy
  image: alpine:latest
  script:
    - ./deploy.sh # Replace with your deployment script
  only:
    - main
  when: manual
```

### Steps to Integrate

1. **Build the Docker Image**:

    ```bash
    docker build -t your-repo/gosast:v1.0.0 .
    docker push your-repo/gosast:v1.0.0
    ```

2. **Update `.gitlab-ci.yml`** with the appropriate Docker registry path.

3. **Commit and Push** the changes to trigger the CI/CD pipeline.

## Contributing

Contributions are welcome! Please follow the guidelines below to contribute to **gosast**.

### How to Contribute

1. **Fork the Repository**:

    Click the "Fork" button on the GitHub repository page to create your own copy.

2. **Clone Your Fork**:

    ```bash
    git clone https://github.com/renatosaksanni/gosast.git
    cd gosast
    ```

3. **Create a New Branch**:

    ```bash
    git checkout -b feature/add-new-rule
    ```

4. **Make Your Changes**:

    Implement your feature or fix.

5. **Commit Your Changes**:

    ```bash
    git commit -m "Add new rule for XYZ vulnerability"
    ```

6. **Push to Your Fork**:

    ```bash
    git push origin feature/add-new-rule
    ```

7. **Create a Pull Request**:

    Go to the original repository and create a pull request with a description of your changes.

### Code Standards

- **Follow Go Conventions**: Ensure your code adheres to Go's coding standards and style.
- **Write Unit Tests**: Provide unit tests for new features or bug fixes.
- **Document Your Code**: Add comments where necessary to explain complex logic.
- **Ensure All Tests Pass**: Before submitting a pull request, make sure all tests pass by running `go test ./...`.

## License

This project is licensed under the [MIT License](LICENSE).
