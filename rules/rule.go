// rules/rule.go

package rules

import (
	"go/ast"
)

type Rule interface {
	Check(node ast.Node, filePath string) []Violation
	Name() string
	Severity() string
}

type Violation struct {
	File     string `json:"file" xml:"file"`
	Line     int    `json:"line" xml:"line"`
	Message  string `json:"message" xml:"message"`
	Severity string `json:"severity" xml:"severity"`
}
