// rules/resource_management/resource_management.go

package resource_management

import (
	"go/ast"
	"gosast/rules"
)

type ResourceManagementRule struct{}

func (r *ResourceManagementRule) Check(node ast.Node, filePath string) []rules.Violation {
	var violations []rules.Violation

	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		selExpr, ok := call.Fun.(*ast.SelectorExpr) // Declare selExpr only once
		if !ok {
			return true
		}

		// Detect file opening without proper closure
		if selExpr.Sel.Name == "Open" || selExpr.Sel.Name == "Create" {
			if !isClosedAfter(call, node) {
				violations = append(violations, rules.Violation{
					File:     filePath,
					Line:     int(call.Pos()),
					Message:  "File opened but not closed (Potential resource leak).",
					Severity: "medium",
				})
			}
		}

		// Detect network connections without proper closure
		if selExpr.Sel.Name == "Dial" || selExpr.Sel.Name == "Listen" {
			if !isClosedAfter(call, node) {
				violations = append(violations, rules.Violation{
					File:     filePath,
					Line:     int(call.Pos()),
					Message:  "Network connection opened but not closed (Potential resource leak).",
					Severity: "medium",
				})
			}
		}

		return true
	})

	return violations
}

// isClosedAfter checks if a file or connection is properly closed after opening.
func isClosedAfter(call *ast.CallExpr, node ast.Node) bool {
	// Simplistic check: Traverse sibling statements in the AST looking for a 'defer file.Close()' pattern.

	parentBlock, ok := node.(*ast.BlockStmt)
	if !ok {
		return false
	}

	for _, stmt := range parentBlock.List {
		deferStmt, ok := stmt.(*ast.DeferStmt)
		if ok {
			callExpr, ok := deferStmt.Call.Fun.(*ast.SelectorExpr)
			if ok && callExpr.Sel.Name == "Close" {
				return true
			}
		}
	}
	return false
}

func (r *ResourceManagementRule) Name() string {
	return "ResourceManagement"
}

func (r *ResourceManagementRule) Severity() string {
	return "medium"
}

func NewResourceManagementRule() rules.Rule {
	return &ResourceManagementRule{}
}
