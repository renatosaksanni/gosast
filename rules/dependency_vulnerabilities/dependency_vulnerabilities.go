// rules/dependency_vulnerabilities/dependency_vulnerabilities.go

package dependency_vulnerabilities

import (
	"go/ast"
	"strings"

	"gosast/rules"
)

type DependencyVulnerabilitiesRule struct{}

// Check inspects the AST node for outdated dependencies that may contain known vulnerabilities.
func (r *DependencyVulnerabilitiesRule) Check(node ast.Node, filePath string) []rules.Violation {
	var violations []rules.Violation

	ast.Inspect(node, func(n ast.Node) bool {
		importSpec, ok := n.(*ast.ImportSpec)
		if !ok {
			return true
		}

		importPath := strings.Trim(importSpec.Path.Value, "\"")
		// Example check: Detect usage of known vulnerable packages
		if strings.Contains(importPath, "github.com/old/vulnerable/package") {
			violations = append(violations, rules.Violation{
				File:     filePath,
				Line:     int(importSpec.Pos()),
				Message:  "Using outdated dependency 'github.com/old/vulnerable/package' with known vulnerabilities.",
				Severity: r.Severity(),
			})
		}

		return true
	})

	return violations
}

func (r *DependencyVulnerabilitiesRule) Name() string {
	return "DependencyVulnerabilities"
}

func (r *DependencyVulnerabilitiesRule) Severity() string {
	return "medium"
}

// NewDependencyVulnerabilitiesRule creates a new instance of DependencyVulnerabilitiesRule.
func NewDependencyVulnerabilitiesRule() rules.Rule {
	return &DependencyVulnerabilitiesRule{}
}
