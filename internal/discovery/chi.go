package discovery

import (
	"go/ast"
	"strings"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/astutil"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/authorization"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

const chiImport = "github.com/go-chi/chi/v5"

// chiRouteMethods maps Chi method names to HTTP methods.
var chiRouteMethods = map[string]models.HTTPMethod{
	"Get":     models.MethodGET,
	"Post":    models.MethodPOST,
	"Put":     models.MethodPUT,
	"Delete":  models.MethodDELETE,
	"Patch":   models.MethodPATCH,
	"Head":    models.MethodHEAD,
	"Options": models.MethodOPTIONS,
}

// ChiDiscoverer discovers endpoints in Chi applications.
type ChiDiscoverer struct {
	authExtractor    *authorization.ChiExtractor
	globalMiddleware []string
}

// NewChiDiscoverer creates a new ChiDiscoverer.
func NewChiDiscoverer() *ChiDiscoverer {
	return &ChiDiscoverer{
		authExtractor: authorization.NewChiExtractor(),
	}
}

// CollectMiddleware scans a source file for router.Use() calls and stores
// the middleware names for cross-file auth detection.
func (d *ChiDiscoverer) CollectMiddleware(source *astutil.ParsedSource) {
	ast.Inspect(source.AST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		callName := astutil.GetCallName(call)

		// Match .Use() calls — could be router.Use(), r.Use(), httpRouter.Use(), etc.
		// Also handle chained calls like httpServer.Router().Use()
		if !strings.HasSuffix(callName, ".Use") {
			// Check for chained selector (e.g., httpServer.Router().Use())
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Use" {
				// This is a .Use() call via chained expression
			} else {
				return true
			}
		}

		// Extract middleware names from all arguments
		for _, arg := range call.Args {
			name := d.extractMiddlewareName(arg)
			if name != "" {
				d.globalMiddleware = append(d.globalMiddleware, name)
			}
		}

		return true
	})
}

// extractMiddlewareName extracts a readable name from a middleware argument expression.
func (d *ChiDiscoverer) extractMiddlewareName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		if ident, ok := e.X.(*ast.Ident); ok {
			return ident.Name + "." + e.Sel.Name
		}
	case *ast.CallExpr:
		// e.g., tokenDataExtractionMiddleware.Middleware() or otelchi.Middleware(...)
		return astutil.GetCallName(e)
	}
	return ""
}

// Framework returns the framework this discoverer handles.
func (d *ChiDiscoverer) Framework() models.Framework {
	return models.FrameworkChi
}

// CanHandle returns true if the source imports Chi.
func (d *ChiDiscoverer) CanHandle(source *astutil.ParsedSource) bool {
	return source.HasImport(chiImport) || source.HasImportPrefix("github.com/go-chi/chi")
}

// Discover finds all Chi endpoints in the source.
func (d *ChiDiscoverer) Discover(source *astutil.ParsedSource) ([]*models.Endpoint, error) {
	var endpoints []*models.Endpoint

	// Find router groups (Route with subrouter)
	groups := d.findGroups(source)

	// Find all route registrations
	ast.Inspect(source.AST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		endpoint := d.extractEndpoint(call, source, groups)
		if endpoint != nil {
			endpoints = append(endpoints, endpoint)
		}

		return true
	})

	return endpoints, nil
}

// ChiGroupInfo stores information about a Chi router group.
type ChiGroupInfo struct {
	Prefix     string
	Middleware []string
	VarName    string
}

// findGroups finds all Chi Route() and Group() calls.
func (d *ChiDiscoverer) findGroups(source *astutil.ParsedSource) map[string]*ChiGroupInfo {
	groups := make(map[string]*ChiGroupInfo)

	ast.Inspect(source.AST, func(n ast.Node) bool {
		// Look for r.Route("/prefix", func(r chi.Router) { ... })
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		callName := astutil.GetCallName(call)
		if !strings.HasSuffix(callName, ".Route") && !strings.HasSuffix(callName, ".Group") {
			return true
		}

		if len(call.Args) < 2 {
			return true
		}

		prefix := astutil.GetStringValue(call.Args[0])

		// Check if second arg is a function that takes a router parameter
		funcLit, ok := call.Args[1].(*ast.FuncLit)
		if !ok {
			return true
		}

		// Get the router parameter name
		if funcLit.Type.Params == nil || len(funcLit.Type.Params.List) == 0 {
			return true
		}

		param := funcLit.Type.Params.List[0]
		if len(param.Names) == 0 {
			return true
		}

		routerVarName := param.Names[0].Name
		groups[routerVarName] = &ChiGroupInfo{
			Prefix:  prefix,
			VarName: routerVarName,
		}

		return true
	})

	return groups
}

// extractEndpoint extracts an endpoint from a route registration call.
func (d *ChiDiscoverer) extractEndpoint(call *ast.CallExpr, source *astutil.ParsedSource, groups map[string]*ChiGroupInfo) *models.Endpoint {
	callName := astutil.GetCallName(call)
	parts := strings.Split(callName, ".")

	if len(parts) < 2 {
		return nil
	}

	receiverVar := parts[0]
	methodName := parts[1]

	// Check if this is a route method
	httpMethod, isRoute := chiRouteMethods[methodName]
	if !isRoute {
		// Check for Method() or MethodFunc()
		if (methodName == "Method" || methodName == "MethodFunc") && len(call.Args) >= 2 {
			methodStr := astutil.GetStringValue(call.Args[0])
			// Capitalize first letter for map lookup (e.g., "get" -> "Get")
			if len(methodStr) > 0 {
				methodStr = strings.ToUpper(methodStr[:1]) + strings.ToLower(methodStr[1:])
			}
			httpMethod, isRoute = chiRouteMethods[methodStr]
			if !isRoute {
				// Try uppercase version
				if m, ok := map[string]models.HTTPMethod{
					"GET":     models.MethodGET,
					"POST":    models.MethodPOST,
					"PUT":     models.MethodPUT,
					"DELETE":  models.MethodDELETE,
					"PATCH":   models.MethodPATCH,
					"HEAD":    models.MethodHEAD,
					"OPTIONS": models.MethodOPTIONS,
				}[methodStr]; ok {
					httpMethod = m
					isRoute = true
				}
			}
			if !isRoute {
				return nil
			}
			// Shift args for Method/MethodFunc case
			call.Args = call.Args[1:]
		} else {
			return nil
		}
	}

	return d.createEndpoint(call, source, groups, receiverVar, []models.HTTPMethod{httpMethod})
}

// createEndpoint creates an Endpoint from a route call.
func (d *ChiDiscoverer) createEndpoint(call *ast.CallExpr, source *astutil.ParsedSource, groups map[string]*ChiGroupInfo, receiverVar string, methods []models.HTTPMethod) *models.Endpoint {
	if len(call.Args) < 2 {
		return nil
	}

	route := astutil.GetStringValue(call.Args[0])
	if route == "" {
		return nil
	}

	// Extract handler name (second argument)
	handlerName := d.extractHandlerName(call.Args[1])

	// Determine group prefix
	prefix := ""
	if group, ok := groups[receiverVar]; ok {
		prefix = group.Prefix
	}

	// Extract authorization info using globally collected middleware
	auth := d.authExtractor.Extract(d.globalMiddleware, source)

	endpoint := &models.Endpoint{
		Route:         route,
		Methods:       methods,
		FilePath:      source.FilePath,
		LineNumber:    astutil.GetLineNumber(source.FileSet, call),
		Framework:     models.FrameworkChi,
		EndpointType:  models.EndpointTypeFunction,
		FunctionName:  handlerName,
		Authorization: auth,
		RouterPrefix:  prefix,
	}

	return endpoint
}

// extractHandlerName extracts the function name from a handler argument.
func (d *ChiDiscoverer) extractHandlerName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		if ident, ok := e.X.(*ast.Ident); ok {
			return ident.Name + "." + e.Sel.Name
		}
	case *ast.CallExpr:
		return astutil.GetCallName(e)
	}
	return ""
}
