// rules/sensitive_data/sensitive_data_exposure.go

package sensitive_data

import (
	"go/ast"
	"strings"

	"gosast/rules"
)

type SensitiveDataExposureRule struct{}

func (r *SensitiveDataExposureRule) Check(node ast.Node, filePath string) []rules.Violation {
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

		if selExpr.Sel.Name == "Println" || selExpr.Sel.Name == "Printf" {
			for _, arg := range call.Args {
				if ident, ok := arg.(*ast.Ident); ok && strings.ToLower(ident.Name) == "password" {
					violations = append(violations, rules.Violation{
						File:     filePath,
						Line:     int(ident.Pos()),
						Message:  "Sensitive data 'password' is being logged",
						Severity: "high",
					})
				}
			}
		}

		return true
	})

	return violations
}

func (r *SensitiveDataExposureRule) Name() string {
	return "SensitiveDataExposure"
}

func (r *SensitiveDataExposureRule) Severity() string {
	return "high"
}

func NewSensitiveDataExposureRule() rules.Rule {
	return &SensitiveDataExposureRule{}
}
