// cmd/gosast/main.go

package main

import (
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"io/ioutil"
	"os"
	"path/filepath"

	"gosast/rules"

	// Import all rule packages
	"gosast/rules/access_control"
	"gosast/rules/authentication"
	"gosast/rules/dependency_vulnerabilities"
	"gosast/rules/error_handling"
	"gosast/rules/injection"
	"gosast/rules/input_validation"
	"gosast/rules/insecure_deserialization"
	"gosast/rules/logging"
	"gosast/rules/path_traversal"
	"gosast/rules/resource_management"
	"gosast/rules/security_misconfig"
	"gosast/rules/sensitive_data"
	"gosast/rules/xss"
	"gosast/rules/xxe"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Linters struct {
		Gosec       struct{ Enabled bool } `yaml:"gosec"`
		Staticcheck struct{ Enabled bool } `yaml:"staticcheck"`
		Custom      struct {
			Enabled bool
			Rules   []string
		} `yaml:"custom"`
	} `yaml:"linters"`
	SeverityLevels map[string][]string `yaml:"severity_levels"`
}

func parseConfig(data []byte) (*Config, error) {
	var config Config
	err := yaml.Unmarshal(data, &config)
	return &config, err
}

func generateReport(report []rules.Violation, format, output string) error {
	var data []byte
	var err error

	switch format {
	case "json":
		data, err = json.MarshalIndent(report, "", "  ")
	case "xml":
		data, err = xml.MarshalIndent(struct {
			Violations []rules.Violation `xml:"violation"`
		}{
			Violations: report,
		}, "", "  ")
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	if err != nil {
		return err
	}

	return ioutil.WriteFile(output, data, 0644)
}

func main() {
	configPath := flag.String("config", "./config/.gosast.yml", "Path to configuration file")
	format := flag.String("format", "json", "Output format (json, xml)")
	output := flag.String("output", "sast-report.json", "Output report file")
	flag.Parse()

	// Read and parse the config file
	configData, err := ioutil.ReadFile(*configPath)
	if err != nil {
		fmt.Printf("Error reading config file: %v\n", err)
		os.Exit(1)
	}

	config, err := parseConfig(configData)
	if err != nil {
		fmt.Printf("Error parsing config file: %v\n", err)
		os.Exit(1)
	}

	var report []rules.Violation
	var ruleInstances []rules.Rule

	// Initialize custom rules based on config
	if config.Linters.Custom.Enabled {
		for _, ruleName := range config.Linters.Custom.Rules {
			switch ruleName {
			case "sql_injection":
				ruleInstances = append(ruleInstances, injection.NewSQLInjectionRule())
			case "command_injection":
				ruleInstances = append(ruleInstances, injection.NewCommandInjectionRule())
			case "xss":
				ruleInstances = append(ruleInstances, xss.NewXSSRule())
			case "weak_authentication":
				ruleInstances = append(ruleInstances, authentication.NewWeakAuthenticationRule())
			case "sensitive_data_exposure":
				ruleInstances = append(ruleInstances, sensitive_data.NewSensitiveDataExposureRule())
			case "xxe":
				ruleInstances = append(ruleInstances, xxe.NewXXERule())
			case "broken_access_control":
				ruleInstances = append(ruleInstances, access_control.NewBrokenAccessControlRule())
			case "security_misconfiguration":
				ruleInstances = append(ruleInstances, security_misconfig.NewSecurityMisconfigurationRule())
			case "insecure_deserialization":
				ruleInstances = append(ruleInstances, insecure_deserialization.NewInsecureDeserializationRule())
			case "dependency_vulnerabilities":
				ruleInstances = append(ruleInstances, dependency_vulnerabilities.NewDependencyVulnerabilitiesRule())
			case "logging":
				ruleInstances = append(ruleInstances, logging.NewLoggingRule())
			case "resource_management":
				ruleInstances = append(ruleInstances, resource_management.NewResourceManagementRule())
			case "input_validation":
				ruleInstances = append(ruleInstances, input_validation.NewInputValidationRule())
			case "path_traversal":
				ruleInstances = append(ruleInstances, path_traversal.NewPathTraversalRule())
			case "error_handling":
				ruleInstances = append(ruleInstances, error_handling.NewErrorHandlingRule())
			default:
				fmt.Printf("Unknown rule: %s\n", ruleName)
			}
		}
	}

	// Scan all Go files in the current directory recursively
	fset := token.NewFileSet()

	err = filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}

		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			fmt.Printf("Error parsing file %s: %v\n", path, err)
			return nil // Skip file that causes an error
		}

		// Apply each rule to the file
		for _, rule := range ruleInstances {
			violations := rule.Check(file, path)
			report = append(report, violations...)
		}

		return nil
	})

	if err != nil {
		fmt.Printf("Error walking the path: %v\n", err)
		os.Exit(1)
	}

	// Generate report
	err = generateReport(report, *format, *output)
	if err != nil {
		fmt.Printf("Error generating report: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("SAST analysis completed successfully.")
}
