// rules/access_control/broken_access_control.go

package access_control

import (
	"go/ast"
	"strings"

	"gosast/rules"
)

type AccessControlRule struct{}

func (r *AccessControlRule) Check(node ast.Node, filePath string) []rules.Violation {
	var violations []rules.Violation

	ast.Inspect(node, func(n ast.Node) bool {
		funcDecl, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}

		if strings.Contains(funcDecl.Name.Name, "HandleFunc") {
			if !hasAuthorizationMiddleware(funcDecl.Body) {
				violations = append(violations, rules.Violation{
					File:     filePath,
					Line:     int(funcDecl.Pos()),
					Message:  "HTTP handler missing authorization middleware",
					Severity: "high",
				})
			}
		}

		return true
	})

	return violations
}

func (r *AccessControlRule) Name() string {
	return "AccessControl"
}

func (r *AccessControlRule) Severity() string {
	return "high"
}

func hasAuthorizationMiddleware(block *ast.BlockStmt) bool {
	// Simplistic check; in real scenarios, analyze the AST for middleware usage
	for _, stmt := range block.List {
		exprStmt, ok := stmt.(*ast.ExprStmt)
		if !ok {
			continue
		}

		call, ok := exprStmt.X.(*ast.CallExpr)
		if !ok {
			continue
		}

		selExpr, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			continue
		}

		if selExpr.Sel.Name == "Use" {
			for _, arg := range call.Args {
				if ident, ok := arg.(*ast.Ident); ok && strings.Contains(ident.Name, "AuthMiddleware") {
					return true
				}
			}
		}
	}
	return false
}

func NewAccessControlRule() rules.Rule {
	return &AccessControlRule{}
}