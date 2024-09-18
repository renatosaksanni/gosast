// rules/authentication/weak_authentication.go

package authentication

import (
	"go/ast"
	"strings"

	"gosast/rules"
)

type WeakAuthenticationRule struct{}

// Check inspects the AST node for weak authentication mechanisms.
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
			if !usesBcrypt(call) {
				violations = append(violations, rules.Violation{
					File:     filePath,
					Line:     int(call.Pos()),
					Message:  "Password hashing is not using bcrypt.",
					Severity: r.Severity(),
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

// usesBcrypt checks if bcrypt is used for password hashing.
func usesBcrypt(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if ident, ok := arg.(*ast.Ident); ok && strings.Contains(ident.Name, "bcrypt") {
			return true
		}
	}
	return false
}

// NewWeakAuthenticationRule creates a new instance of WeakAuthenticationRule.
func NewWeakAuthenticationRule() rules.Rule {
	return &WeakAuthenticationRule{}
}
