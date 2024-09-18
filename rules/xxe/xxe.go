// rules/xxe/xxe.go

package xxe

import (
	"go/ast"
	"strings"

	"gosast/rules"
)

type XXERule struct{}

// Check inspects the AST node for XML External Entities (XXE) vulnerabilities.
func (r *XXERule) Check(node ast.Node, filePath string) []rules.Violation {
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

		if selExpr.Sel.Name == "Parse" || selExpr.Sel.Name == "Unmarshal" {
			if strings.Contains(getSource(node), "xml.Decoder") || strings.Contains(getSource(node), "xml.Unmarshal") {
				violations = append(violations, rules.Violation{
					File:     filePath,
					Line:     int(call.Pos()),
					Message:  "XML parsing without disabling external entities (XXE vulnerability).",
					Severity: r.Severity(),
				})
			}
		}

		return true
	})

	return violations
}

func (r *XXERule) Name() string {
	return "XXE"
}

func (r *XXERule) Severity() string {
	return "high"
}

// getSource is a placeholder for retrieving the source code as a string.
// Implement this function using token.FileSet for accurate source retrieval.
func getSource(node ast.Node) string {
	// Implement source retrieval if needed.
	return ""
}

// NewXXERule creates a new instance of XXERule.
func NewXXERule() rules.Rule {
	return &XXERule{}
}
