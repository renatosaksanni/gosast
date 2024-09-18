// rules/input_validation/input_validation.go

package input_validation

import (
	"go/ast"
	"strings"

	"gosast/rules"
)

type InputValidationRule struct{}

func (r *InputValidationRule) Check(node ast.Node, filePath string) []rules.Violation {
	var violations []rules.Violation

	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Check if user input is being used without validation or sanitization
		if isUnvalidatedUserInput(call) {
			violations = append(violations, rules.Violation{
				File:     filePath,
				Line:     int(call.Pos()),
				Message:  "User input used without validation or sanitization (Potential injection or buffer overflow vulnerability).",
				Severity: "high",
			})
		}

		return true
	})

	return violations
}

// isUnvalidatedUserInput checks if a function call uses user input directly without validation.
func isUnvalidatedUserInput(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		ident, ok := arg.(*ast.Ident)
		if ok && strings.Contains(ident.Name, "input") {
			// In real scenarios, check for actual user input sources like HTTP requests
			return !containsSanitization(call)
		}
	}
	return false
}

// containsSanitization checks if input is sanitized before use
func containsSanitization(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		ident, ok := arg.(*ast.Ident)
		if ok && strings.Contains(ident.Name, "sanitize") {
			return true
		}
	}
	return false
}

func (r *InputValidationRule) Name() string {
	return "InputValidation"
}

func (r *InputValidationRule) Severity() string {
	return "high"
}

func NewInputValidationRule() rules.Rule {
	return &InputValidationRule{}
}
