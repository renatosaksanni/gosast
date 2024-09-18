// rules/path_traversal/path_traversal.go

package path_traversal

import (
	"go/ast"
	"strings"

	"gosast/rules"
)

type PathTraversalRule struct{}

func (r *PathTraversalRule) Check(node ast.Node, filePath string) []rules.Violation {
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

		if selExpr.Sel.Name == "Join" && strings.Contains(getSource(node), "filepath.Join") {
			if !containsSanitization(call) {
				violations = append(violations, rules.Violation{
					File:     filePath,
					Line:     int(call.Pos()),
					Message:  "Path joined without sanitization, potential path traversal.",
					Severity: "high",
				})
			}
		}

		return true
	})

	return violations
}

func (r *PathTraversalRule) Name() string {
	return "PathTraversal"
}

func (r *PathTraversalRule) Severity() string {
	return "high"
}

func containsSanitization(call *ast.CallExpr) bool {
	// Simplistic check: looks for 'sanitizePath' in arguments
	for _, arg := range call.Args {
		if ident, ok := arg.(*ast.Ident); ok && strings.Contains(ident.Name, "sanitize") {
			return true
		}
	}
	return false
}

func NewPathTraversalRule() rules.Rule {
	return &PathTraversalRule{}
}

// Placeholder function: Implement proper source retrieval if needed
func getSource(node ast.Node) string {
	return ""
}
