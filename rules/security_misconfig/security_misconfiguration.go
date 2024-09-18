// rules/security_misconfig/security_misconfiguration.go

package security_misconfig

import (
	"go/ast"
	"strings"

	"gosast/rules"
)

type SecurityMisconfigurationRule struct{}

// Check inspects the AST node for security misconfigurations.
func (r *SecurityMisconfigurationRule) Check(node ast.Node, filePath string) []rules.Violation {
	var violations []rules.Violation

	ast.Inspect(node, func(n ast.Node) bool {
		funcDecl, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}

		// Example: Detect if debug mode is enabled
		if strings.Contains(funcDecl.Name.Name, "EnableDebug") {
			violations = append(violations, rules.Violation{
				File:     filePath,
				Line:     int(funcDecl.Pos()),
				Message:  "Debug mode is enabled, which can lead to information disclosure.",
				Severity: r.Severity(),
			})
		}

		return true
	})

	return violations
}

func (r *SecurityMisconfigurationRule) Name() string {
	return "SecurityMisconfiguration"
}

func (r *SecurityMisconfigurationRule) Severity() string {
	return "high"
}

// NewSecurityMisconfigurationRule creates a new instance of SecurityMisconfigurationRule.
func NewSecurityMisconfigurationRule() rules.Rule {
	return &SecurityMisconfigurationRule{}
}
