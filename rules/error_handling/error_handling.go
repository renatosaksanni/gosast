// rules/error_handling/error_handling.go

package error_handling

import (
	"go/ast"
	"strings"

	"gosast/rules"
)

type ErrorHandlingRule struct{}

func (r *ErrorHandlingRule) Check(node ast.Node, filePath string) []rules.Violation {
	var violations []rules.Violation

	ast.Inspect(node, func(n ast.Node) bool {
		assignStmt, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}

		for _, rhs := range assignStmt.Rhs {
			call, ok := rhs.(*ast.CallExpr)
			if !ok {
				continue
			}

			selExpr, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				continue
			}

			if selExpr.Sel.Name == "Errorf" || selExpr.Sel.Name == "Println" {
				for _, arg := range call.Args {
					if ident, ok := arg.(*ast.Ident); ok && strings.Contains(strings.ToLower(ident.Name), "err") {
						// Check if the error is properly handled
						if !isErrorHandled(assignStmt) {
							violations = append(violations, rules.Violation{
								File:     filePath,
								Line:     int(ident.Pos()),
								Message:  "Error is logged but not properly handled.",
								Severity: "low",
							})
						}
					}
				}
			}
		}

		return true
	})

	return violations
}

func (r *ErrorHandlingRule) Name() string {
	return "ErrorHandling"
}

func (r *ErrorHandlingRule) Severity() string {
	return "low"
}

func isErrorHandled(assignStmt *ast.AssignStmt) bool {
	// Simplistic check: ensure that 'return err' is called after logging
	// This requires more complex analysis in real scenarios
	// Here, we'll assume it's not handled
	return false
}

func NewErrorHandlingRule() rules.Rule {
	return &ErrorHandlingRule{}
}
