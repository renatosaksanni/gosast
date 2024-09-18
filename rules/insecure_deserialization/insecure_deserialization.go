// rules/insecure_deserialization/insecure_deserialization.go

package insecure_deserialization

import (
	"go/ast"
	"strings"

	"gosast/rules"
)

type InsecureDeserializationRule struct{}

// Check inspects the AST node for insecure deserialization vulnerabilities.
func (r *InsecureDeserializationRule) Check(node ast.Node, filePath string) []rules.Violation {
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

		if selExpr.Sel.Name == "Unmarshal" || selExpr.Sel.Name == "Decode" {
			if strings.Contains(getSource(node), "json.Unmarshal") || strings.Contains(getSource(node), "gob.Decode") {
				violations = append(violations, rules.Violation{
					File:     filePath,
					Line:     int(call.Pos()),
					Message:  "Deserializing data without validation (Insecure Deserialization).",
					Severity: r.Severity(),
				})
			}
		}

		return true
	})

	return violations
}

func (r *InsecureDeserializationRule) Name() string {
	return "InsecureDeserialization"
}

func (r *InsecureDeserializationRule) Severity() string {
	return "medium"
}

// getSource is a placeholder for retrieving the source code as a string.
// Implement this function using token.FileSet for accurate source retrieval.
func getSource(node ast.Node) string {
	// Implement source retrieval if needed.
	return ""
}

// NewInsecureDeserializationRule creates a new instance of InsecureDeserializationRule.
func NewInsecureDeserializationRule() rules.Rule {
	return &InsecureDeserializationRule{}
}
