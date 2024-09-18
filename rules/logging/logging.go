// rules/logging/logging.go

package logging

import (
	"go/ast"
	"strings"

	"gosast/rules"
)

type LoggingRule struct{}

// Check inspects the AST node for insufficient logging and monitoring.
func (r *LoggingRule) Check(node ast.Node, filePath string) []rules.Violation {
	var violations []rules.Violation

	ast.Inspect(node, func(n ast.Node) bool {
		funcDecl, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}

		// Example: Detect if critical functions lack logging
		if strings.Contains(funcDecl.Name.Name, "Handle") {
			if !hasLogging(funcDecl.Body) {
				violations = append(violations, rules.Violation{
					File:     filePath,
					Line:     int(funcDecl.Pos()),
					Message:  "HTTP handler missing logging statements for critical operations.",
					Severity: r.Severity(),
				})
			}
		}

		return true
	})

	return violations
}

func (r *LoggingRule) Name() string {
	return "Logging"
}

func (r *LoggingRule) Severity() string {
	return "medium"
}

// hasLogging checks if logging statements are present in the function body.
func hasLogging(block *ast.BlockStmt) bool {
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

		if selExpr.Sel.Name == "Printf" || selExpr.Sel.Name == "Println" || selExpr.Sel.Name == "Errorf" {
			return true
		}
	}
	return false
}

// NewLoggingRule creates a new instance of LoggingRule.
func NewLoggingRule() rules.Rule {
	return &LoggingRule{}
}
