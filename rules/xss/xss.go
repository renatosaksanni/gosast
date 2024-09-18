// rules/xss/xss.go

package xss

import (
	"go/ast"
	"strings"

	"gosast/rules"
)

type XSSRule struct{}

func (r *XSSRule) Check(node ast.Node, filePath string) []rules.Violation {
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

		if selExpr.Sel.Name == "Execute" || selExpr.Sel.Name == "ExecuteTemplate" {
			if !containsSanitization(call) {
				violations = append(violations, rules.Violation{
					File:     filePath,
					Line:     int(call.Pos()),
					Message:  "HTML template execution without proper sanitization (XSS vulnerability)",
					Severity: "high",
				})
			}
		}

		return true
	})

	return violations
}

func (r *XSSRule) Name() string {
	return "XSS"
}

func (r *XSSRule) Severity() string {
	return "high"
}

func containsSanitization(call *ast.CallExpr) bool {
	// Simplistic check; in real scenarios, more robust analysis is needed
	for _, arg := range call.Args {
		if ident, ok := arg.(*ast.Ident); ok && strings.Contains(ident.Name, "sanitize") {
			return true
		}
	}
	return false
}

func NewXSSRule() rules.Rule {
	return &XSSRule{}
}
