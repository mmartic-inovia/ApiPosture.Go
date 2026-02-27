package analysis

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/classification"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/config"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/discovery"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/openapi"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/rules"
)

// ProjectAnalyzer orchestrates the scanning process for a project.
type ProjectAnalyzer struct {
	config      *config.Config
	loader      *SourceLoader
	discoverers []discovery.Discoverer
	classifier  *classification.Classifier
	ruleEngine  *rules.Engine
}

// NewProjectAnalyzer creates a new ProjectAnalyzer.
func NewProjectAnalyzer(cfg *config.Config) *ProjectAnalyzer {
	if cfg == nil {
		cfg = config.NewConfig()
	}

	return &ProjectAnalyzer{
		config:      cfg,
		loader:      NewSourceLoader(),
		discoverers: discovery.AllDiscoverers(),
		classifier:  classification.NewClassifier(),
		ruleEngine:  rules.NewEngine(cfg.GetActiveRules()),
	}
}

// Analyze analyzes a project for API security issues.
func (a *ProjectAnalyzer) Analyze(path string) (*models.ScanResult, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	result := models.NewScanResult(absPath)

	// Get files to scan
	files, err := a.getFiles(absPath)
	if err != nil {
		return nil, err
	}
	result.FilesScanned = files

	// Phase 1: Collect global middleware from all files (enables cross-file auth detection)
	for _, file := range files {
		a.collectMiddleware(file)
	}

	// Phase 2: Scan each file for endpoints
	for _, file := range files {
		a.scanFile(file, result)
	}

	// Phase 3: Overlay OpenAPI security info if spec is configured
	if a.config.OpenAPISpec != "" {
		if err := a.applyOpenAPISecurity(absPath, result); err != nil {
			// Non-fatal: log as parse error and continue with AST-based classification
			result.ParseErrors["openapi:"+a.config.OpenAPISpec] = err.Error()
		}
	}

	// Phase 4: Apply public_routes config overrides
	a.applyPublicRoutes(result)

	// Classify all endpoints
	a.classifier.ClassifyAll(result.Endpoints)

	// Run security rules
	findings := a.ruleEngine.EvaluateAll(result.Endpoints)

	// Apply suppressions
	for _, finding := range findings {
		suppressed, reason := a.config.IsSuppressed(finding.RuleID, finding.Endpoint.FullRoute())
		if suppressed {
			finding.Suppressed = true
			finding.SuppressionReason = reason
		}
	}

	// Filter by rule enablement
	var enabledFindings []*models.Finding
	for _, f := range findings {
		if a.config.IsRuleEnabled(f.RuleID) {
			enabledFindings = append(enabledFindings, f)
		}
	}

	result.Findings = enabledFindings
	result.EndTime = time.Now()

	return result, nil
}

// getFiles returns the list of Go files to scan.
func (a *ProjectAnalyzer) getFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		if filepath.Ext(path) == ".go" {
			return []string{path}, nil
		}
		return []string{}, nil
	}

	return GetGoFiles(path, a.config.ExcludePatterns)
}

// collectMiddleware scans a file for global middleware registrations.
// Note: we skip the CanHandle() check here because middleware is often
// registered in files that don't directly import the framework package
// (e.g., using a wrapper like httpServer.Router().Use(...)).
func (a *ProjectAnalyzer) collectMiddleware(filePath string) {
	source, errStr := a.loader.TryParseFile(filePath)
	if errStr != "" {
		return
	}

	for _, disc := range a.discoverers {
		if collector, ok := disc.(discovery.MiddlewareCollector); ok {
			collector.CollectMiddleware(source)
		}
	}
}

// applyOpenAPISecurity loads an OpenAPI spec and overlays per-route security
// info onto discovered endpoints, overriding AST-based auth detection.
func (a *ProjectAnalyzer) applyOpenAPISecurity(projectPath string, result *models.ScanResult) error {
	specPath := a.config.OpenAPISpec
	if !filepath.IsAbs(specPath) {
		specPath = filepath.Join(projectPath, specPath)
	}

	spec, err := openapi.ParseFile(specPath)
	if err != nil {
		return fmt.Errorf("loading OpenAPI spec: %w", err)
	}

	for _, ep := range result.Endpoints {
		route := ep.FullRoute()
		method := ""
		if len(ep.Methods) > 0 {
			method = string(ep.Methods[0])
		}

		info := spec.LookupRoute(route, method)
		if info == nil {
			continue
		}

		if info.IsPublic {
			// security: [] — explicitly public, override any middleware-based auth
			ep.Authorization = models.AuthorizationInfo{
				AllowsAnonymous:  true,
				Source:           "openapi",
				Roles:            []string{},
				Scopes:           []string{},
				Permissions:      []string{},
				Policies:         []string{},
				AuthDependencies: []string{},
			}
		} else if len(info.Scopes) > 0 || len(info.Schemes) > 0 {
			// Has specific security requirements
			ep.Authorization.RequiresAuth = true
			ep.Authorization.Source = "openapi"
			ep.Authorization.Scopes = mergeStrings(ep.Authorization.Scopes, info.Scopes)
			ep.Authorization.AuthDependencies = mergeStrings(ep.Authorization.AuthDependencies, info.Schemes)
		}
	}

	return nil
}

// applyPublicRoutes marks routes declared in public_routes config as explicitly public.
func (a *ProjectAnalyzer) applyPublicRoutes(result *models.ScanResult) {
	for _, ep := range result.Endpoints {
		route := ep.FullRoute()
		if isPublic, _ := a.config.IsPublicRoute(route); isPublic {
			ep.Authorization = models.AuthorizationInfo{
				AllowsAnonymous:  true,
				Source:           "config",
				Roles:            []string{},
				Scopes:           []string{},
				Permissions:      []string{},
				Policies:         []string{},
				AuthDependencies: []string{},
			}
		}
	}
}

func mergeStrings(a, b []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// scanFile scans a single file for endpoints.
func (a *ProjectAnalyzer) scanFile(filePath string, result *models.ScanResult) {
	source, errStr := a.loader.TryParseFile(filePath)
	if errStr != "" {
		result.ParseErrors[filePath] = errStr
		return
	}

	// Try each discoverer
	for _, disc := range a.discoverers {
		if disc.CanHandle(source) {
			result.FrameworksDetected[disc.Framework()] = true

			endpoints, err := disc.Discover(source)
			if err != nil {
				continue
			}

			result.Endpoints = append(result.Endpoints, endpoints...)
		}
	}
}
