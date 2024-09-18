// rules/injection/command_injection.go

package injection

import (
	"go/ast"
	"strings"

	"gosast/rules"
)

type CommandInjectionRule struct{}

func (r *CommandInjectionRule) Check(node ast.Node, filePath string) []rules.Violation {
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

		if selExpr.Sel.Name == "Command" || selExpr.Sel.Name == "CombinedOutput" {
			for _, arg := range call.Args {
				if ident, ok := arg.(*ast.Ident); ok && strings.Contains(ident.Name, "input") {
					violations = append(violations, rules.Violation{
						File:     filePath,
						Line:     int(arg.Pos()),
						Message:  "Potential Command Injection vulnerability detected.",
						Severity: "critical",
					})
				}
			}
		}

		return true
	})

	return violations
}

func (r *CommandInjectionRule) Name() string {
	return "CommandInjection"
}

func (r *CommandInjectionRule) Severity() string {
	return "critical"
}

func NewCommandInjectionRule() rules.Rule {
	return &CommandInjectionRule{}
}
