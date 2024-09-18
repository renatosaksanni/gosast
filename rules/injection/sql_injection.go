// rules/injection/sql_injection.go

package injection

import (
	"go/ast"
	"strings"

	"go/token"
	"gosast/rules"
)

type SQLInjectionRule struct{}

func (r *SQLInjectionRule) Check(node ast.Node, filePath string) []rules.Violation {
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

		if selExpr.Sel.Name == "Exec" || selExpr.Sel.Name == "Query" {
			if len(call.Args) > 0 {
				arg, ok := call.Args[0].(*ast.BasicLit)
				if ok && arg.Kind == token.STRING {
					query := arg.Value
					upperQuery := strings.ToUpper(query)
					if strings.Contains(upperQuery, "SELECT") || strings.Contains(upperQuery, "INSERT") {
						violations = append(violations, rules.Violation{
							File:     filePath,
							Line:     int(arg.Pos()),
							Message:  "Potential SQL Injection vulnerability detected.",
							Severity: "critical",
						})
					}
				}
			}
		}

		return true
	})

	return violations
}

func (r *SQLInjectionRule) Name() string {
	return "SQLInjection"
}

func (r *SQLInjectionRule) Severity() string {
	return "critical"
}

func NewSQLInjectionRule() rules.Rule {
	return &SQLInjectionRule{}
}
