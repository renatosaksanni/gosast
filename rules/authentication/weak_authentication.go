// rules/authentication/weak_authentication.go

package authentication

import (
	"go/ast"
	"strings"

	"gosast/rules"
)

type WeakAuthenticationRule struct{}

func (r *WeakAuthenticationRule) Check(node ast.Node, filePath string) []rules.Violation {
	var violations []rules.Violation

	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		selExpr, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		if selExpr.Sel.Name == "GenerateFromPassword" {
			// Check if bcrypt is used
			if !usesBcrypt(call) {
				violations = append(violations, rules.Violation{
					File:     filePath,
					Line:     int(call.Pos()),
					Message:  "Password hashing is not using bcrypt",
					Severity: "critical",
				})
			}
		}

		return true
	})

	return violations
}

func (r *WeakAuthenticationRule) Name() string {
	return "WeakAuthentication"
}

func (r *WeakAuthenticationRule) Severity() string {
	return "critical"
}

func usesBcrypt(call *ast.CallExpr) bool {
	// Simplistic check; in real scenarios, analyze the import path and usage
	for _, arg := range call.Args {
		if ident, ok := arg.(*ast.Ident); ok && strings.Contains(ident.Name, "bcrypt") {
			return true
		}
	}
	return false
}

func NewWeakAuthenticationRule() rules.Rule {
	return &WeakAuthenticationRule{}
}
