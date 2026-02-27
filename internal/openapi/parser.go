// Package openapi provides OpenAPI specification parsing for security analysis.
package openapi

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// SecurityInfo contains parsed security requirements for a single operation.
type SecurityInfo struct {
	// IsPublic is true when the operation explicitly has `security: []`.
	IsPublic bool
	// Scopes contains OAuth2/OIDC scopes required by the operation.
	Scopes []string
	// Schemes contains the security scheme names (e.g., "oauth2", "bearer").
	Schemes []string
}

// RouteKey uniquely identifies an operation by path and HTTP method.
type RouteKey struct {
	Path   string // e.g., "/users/{user_id}"
	Method string // e.g., "GET"
}

// Spec holds the parsed security requirements from an OpenAPI specification.
type Spec struct {
	// Routes maps each path+method to its security requirements.
	Routes map[RouteKey]*SecurityInfo
	// BasePath is the common path prefix extracted from server URLs (e.g., "/v1").
	BasePath string
	// GlobalSecurity is the top-level security requirement (inherited by operations without their own).
	GlobalSecurity *SecurityInfo
}

// ParseFile parses an OpenAPI YAML file and extracts per-route security info.
func ParseFile(filePath string) (*Spec, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading OpenAPI spec: %w", err)
	}

	// Unmarshal into generic maps to avoid yaml.v3 named type issues
	var doc map[string]interface{}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing OpenAPI spec: %w", err)
	}

	spec := &Spec{
		Routes: make(map[RouteKey]*SecurityInfo),
	}

	// Extract base path from server URLs, preferring concrete URLs without template variables
	if servers, ok := toSlice(doc["servers"]); ok {
		for _, srv := range servers {
			if srvMap, ok := toMap(srv); ok {
				if url, ok := srvMap["url"].(string); ok && !strings.Contains(url, "{") {
					spec.BasePath = extractBasePath(url)
					break
				}
			}
		}
		// Fallback to first server if all have templates
		if spec.BasePath == "" {
			if srvMap, ok := toMap(servers[0]); ok {
				if url, ok := srvMap["url"].(string); ok {
					spec.BasePath = extractBasePath(url)
				}
			}
		}
	}

	// Parse global security
	if globalSec, ok := toSlice(doc["security"]); ok {
		spec.GlobalSecurity = parseSecurityList(globalSec)
	}

	// Parse per-path, per-method security
	paths, ok := toMap(doc["paths"])
	if !ok {
		return spec, nil
	}

	for path, pathItemRaw := range paths {
		pathItem, ok := toMap(pathItemRaw)
		if !ok {
			continue
		}

		for method, opRaw := range pathItem {
			method = strings.ToUpper(method)
			if !isHTTPMethod(method) {
				continue
			}

			opMap, ok := toMap(opRaw)
			if !ok {
				continue
			}

			key := RouteKey{Path: path, Method: method}

			secRaw, hasSecurity := opMap["security"]
			if !hasSecurity {
				// Inherits global security
				if spec.GlobalSecurity != nil {
					info := *spec.GlobalSecurity
					spec.Routes[key] = &info
				}
				continue
			}

			secList, ok := toSlice(secRaw)
			if !ok {
				continue
			}

			// security: [] means explicitly public
			if len(secList) == 0 {
				spec.Routes[key] = &SecurityInfo{IsPublic: true}
				continue
			}

			// Parse security requirement objects
			spec.Routes[key] = parseSecurityList(secList)
		}
	}

	return spec, nil
}

// LookupRoute finds security info for a discovered route.
// It handles base path matching: a discovered route "/v1/users" matches
// an OpenAPI path "/users" when basePath is "/v1".
func (s *Spec) LookupRoute(route, method string) *SecurityInfo {
	method = strings.ToUpper(method)

	// Try direct match first
	if info, ok := s.Routes[RouteKey{Path: route, Method: method}]; ok {
		return info
	}

	// Try stripping the base path from the discovered route
	if s.BasePath != "" {
		stripped := strings.TrimPrefix(route, s.BasePath)
		if stripped != route { // prefix was actually present
			if info, ok := s.Routes[RouteKey{Path: stripped, Method: method}]; ok {
				return info
			}
		}
	}

	return nil
}

// toMap converts an interface{} to a string-keyed map regardless of the
// concrete named type that yaml.v3 may have used during unmarshaling.
func toMap(v interface{}) (map[string]interface{}, bool) {
	if v == nil {
		return nil, false
	}
	if m, ok := v.(map[string]interface{}); ok {
		return m, true
	}
	return nil, false
}

// toSlice converts an interface{} to a slice of interface{}.
func toSlice(v interface{}) ([]interface{}, bool) {
	if v == nil {
		return nil, false
	}
	if s, ok := v.([]interface{}); ok {
		return s, true
	}
	return nil, false
}

func extractBasePath(serverURL string) string {
	url := serverURL

	// Remove scheme and host if present
	if idx := strings.Index(url, "://"); idx >= 0 {
		url = url[idx+3:]
		if idx := strings.Index(url, "/"); idx >= 0 {
			url = url[idx:]
		} else {
			return ""
		}
	}

	url = strings.TrimSuffix(url, "/")

	if url == "" || url == "/" {
		return ""
	}

	return url
}

func isHTTPMethod(s string) bool {
	switch s {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE":
		return true
	}
	return false
}

func parseSecurityList(secList []interface{}) *SecurityInfo {
	if len(secList) == 0 {
		return &SecurityInfo{IsPublic: true}
	}

	info := &SecurityInfo{}
	for _, item := range secList {
		reqMap, ok := toMap(item)
		if !ok {
			continue
		}
		for scheme, scopesRaw := range reqMap {
			info.Schemes = append(info.Schemes, scheme)
			if scopesList, ok := toSlice(scopesRaw); ok {
				for _, s := range scopesList {
					if str, ok := s.(string); ok {
						info.Scopes = append(info.Scopes, str)
					}
				}
			}
		}
	}
	return info
}
