# Review: ApiPosture.Go

Nice concept and clean codebase — API security posture scanning via Go AST analysis is a genuinely useful tool. The architecture is solid (discoverer interface, pluggable rules, framework-agnostic classification). I tested it against a real Chi production API (~175 endpoints) and found several issues that would affect most Chi users and some that apply generally. All are fixable.

---

## 1. `GetStringValue()` doesn't resolve `http.Method*` constants (Bug - Chi)

**Impact**: `router.Method()` / `router.MethodFunc()` detection is broken for the most common usage pattern.

The `extractEndpoint` code (chi.go:196) already handles `Method()`/`MethodFunc()` calls, but it relies on `GetStringValue()` to extract the HTTP method from the first argument. The problem is `GetStringValue()` (helpers.go:56) only handles `*ast.BasicLit` (string literals like `"GET"`). In practice, nearly everyone uses stdlib constants:

```go
// This is what people write:
router.Method(http.MethodPost, "/users", handler)

// This is what the tool expects:
router.Method("POST", "/users", handler)
```

`http.MethodPost` is an `*ast.SelectorExpr` in the AST, not a `*ast.BasicLit`, so `GetStringValue` returns `""` and the route is silently skipped.

**Fix**: Add an `*ast.SelectorExpr` case to `GetStringValue` that resolves well-known `net/http` method constants (`http.MethodGet` -> `"GET"`, etc.). These are a fixed set of 9 values, easy to map.

---

## 2. Chi middleware detection is a no-op (Bug - Chi)

**Impact**: Every Chi endpoint is classified as `public`, regardless of auth middleware.

In chi.go:252, the auth extractor is called with `nil` middleware:

```go
auth := d.authExtractor.Extract(nil, source)
```

The `ChiExtractor.Extract()` iterates over the `middleware` slice (chi_auth.go:20), but since it's `nil`, the loop body never executes. The auth info stays at defaults (`RequiresAuth: false`), and the classifier maps that to `public`.

By contrast, the Gin discoverer (gin.go:202) correctly collects middleware from `Group()` calls and passes them to its extractor.

**Fix**: Scan for `router.Use()` calls in the AST and extract middleware function names. Pass them to `ChiExtractor.Extract()`. See point 3 for the cross-file challenge this creates.

---

## 3. Per-file scanning misses cross-file middleware (Architecture)

**Impact**: Auth middleware registered in one file is invisible to routes discovered in another file.

The analyzer (analyzer.go:56-63) processes each file independently — `scanFile()` calls `disc.Discover(source)` on a single `ParsedSource`. In Chi (and most real-world Go apps), middleware is registered in a different file/package than routes:

```go
// auth/module.go
router.Use(authMiddleware.Verify())

// routes/module.go (separate file)
router.Method(http.MethodGet, "/users", handler)
```

The discoverer never sees both in the same `ParsedSource`, so it can't connect them.

**Fix**: Add a two-phase scan to the analyzer. Introduce an optional `MiddlewareCollector` interface:

```go
type MiddlewareCollector interface {
    CollectMiddleware(source *ParsedSource)
}
```

Phase 1: iterate all files, call `CollectMiddleware()` on discoverers that implement it. Phase 2: normal `Discover()` with the collected middleware available. This keeps the `Discoverer` interface backward-compatible.

**Important subtlety**: middleware is often registered in files that don't directly import the framework package (e.g., via a wrapper: `httpServer.Router().Use(...)`). The middleware collection phase should not be gated by `CanHandle()` (which checks for framework imports), otherwise those files are skipped entirely.

---

## 4. `GetCallName()` can't resolve chained calls (Bug - AST)

**Impact**: Calls like `httpServer.Router().Use(...)` are not recognized as `.Use()` calls.

`GetCallName()` (helpers.go:11) handles `*ast.SelectorExpr` where `X` is an `*ast.Ident` (e.g., `router.Use`), and chains of selectors (e.g., `a.b.c`). But when `X` is a `*ast.CallExpr` (a method call result, e.g., `httpServer.Router()` in `httpServer.Router().Use()`), `selectorToString()` hits the `default` branch and returns just `"Use"` without context.

**Fix**: Add a `*ast.CallExpr` case to `selectorToString()` that recursively resolves the call, e.g., returning `"httpServer.Router().Use"`. Or simpler: when looking for `.Use()` calls, check `sel.Sel.Name == "Use"` directly on the `SelectorExpr` instead of relying on `GetCallName()`.

---

## 5. `Handle()` and `HandleFunc()` not recognized for Chi (Missing feature)

**Impact**: Routes registered via `router.Handle("/path", handler)` or `router.HandleFunc("/path", handler)` are silently skipped.

The `chiRouteMethods` map (chi.go:15) only includes `Get`, `Post`, `Put`, `Delete`, `Patch`, `Head`, `Options`. The `Method`/`MethodFunc` fallback (chi.go:196) only triggers for those exact names. Chi's `Handle` and `HandleFunc` methods accept all HTTP methods but aren't in either check.

**Fix**: Add `Handle` and `HandleFunc` to the detection logic. Since these don't specify an HTTP method, they could be treated as matching all methods (similar to Gin's `Any()`), or classified as `UNKNOWN` with a note.

---

## 6. Handler name shows `http.HandlerFunc` instead of actual function (UX)

**Impact**: When routes use `router.Method(http.MethodGet, "/path", http.HandlerFunc(controller.GetUsers))`, the handler name in the output shows `http.HandlerFunc` instead of `controller.GetUsers`.

`extractHandlerName` (chi.go:270) handles `*ast.CallExpr` by calling `GetCallName()`, which returns the outer function name (`http.HandlerFunc`). It doesn't unwrap the inner argument.

**Fix**: When the call name is `http.HandlerFunc` (or any type conversion wrapper), recurse into `call.Args[0]` to extract the actual handler name:

```go
case *ast.CallExpr:
    name := astutil.GetCallName(e)
    // Unwrap type conversions like http.HandlerFunc(actualHandler)
    if name == "http.HandlerFunc" && len(e.Args) == 1 {
        return d.extractHandlerName(e.Args[0])
    }
    return name
```

---

## 7. AP001 and AP008 are functionally identical (Rules)

**Impact**: Every unprotected endpoint fires both AP001 and AP008 with the same severity (High), creating noise.

Both rules check the exact same condition: `ClassificationPublic && !AllowsAnonymous && !RequiresAuth && no AuthDependencies && no specific requirements`. The only difference is AP008 adds a framework-specific recommendation string.

**Fix**: Either merge them into a single rule with framework-specific recommendations, or differentiate their conditions. For example, AP001 could specifically target endpoints that *should* have auth but don't (heuristic: write endpoints, admin paths), while AP008 remains a catch-all informational rule at a lower severity.

---

## 8. AP002 and AP004 overlap on the same condition (Rules)

**Impact**: Similar to AP001/AP008. Both target public write endpoints, but AP004 fires on public writes *without* `AllowsAnonymous`, and AP002 fires on those *with* `AllowsAnonymous`. They're mutually exclusive by design, which is correct. However, if the tool successfully detects middleware but an endpoint is still public (e.g., OpenAPI `security: []`), only AP002 fires — this is fine. The issue is just that when middleware detection fails (which is common for Chi today), AP004 fires on EVERY write endpoint since they all appear as public-without-intent. Consider tying AP004 severity to confidence level.

---

## 9. No OpenAPI spec integration (Missing feature)

**Impact**: Many Go API projects maintain an OpenAPI spec as their source of truth for route security. The tool ignores this and relies solely on AST analysis, which can't capture runtime behaviors like conditional middleware or config-driven path exclusions.

**Why it matters**: OpenAPI specs explicitly declare `security` per-operation. Routes with `security: []` are intentionally public; routes with `security: [{oauth2: [...]}]` have specific scopes. This is far more accurate than heuristic middleware name matching.

**Fix**: Add an optional `openapi_spec` field to `.apiposture.yaml`. When provided, parse the spec (it already depends on `gopkg.in/yaml.v3`), extract per-route security definitions, and overlay them onto discovered endpoints before classification. This lets the tool correctly classify routes even when AST analysis can't determine auth status.

**One gotcha for implementation**: when parsing YAML into `map[string]interface{}` with named map types, `yaml.v3` creates values of the named type for nested maps. Type assertions against `map[string]interface{}` will fail even though the underlying type is identical. Use a single `map[string]interface{}` throughout or add a conversion helper.

---

## 10. No `public_routes` config for runtime-excluded paths (Missing feature)

**Impact**: Many Go APIs exclude specific routes from auth middleware at runtime (health checks, metrics, webhook endpoints). The tool has no way to represent this — `suppressions` hide findings but don't change classification, so suppressed routes still show as `authenticated` in the endpoint list, which is misleading.

**Fix**: Add a `public_routes` section to `.apiposture.yaml` that explicitly marks routes as intentionally public, with support for prefix matching (trailing `*`):

```yaml
public_routes:
  - route: /health
    reason: "Health check endpoint, no auth required"
  - route: /v1/public/*
    reason: "Public API routes, intentionally unauthenticated"
```

This overrides middleware-based classification and gives accurate results for routes where auth is handled outside the middleware chain.

---

## Summary

| # | Issue | Type | Severity |
|---|-------|------|----------|
| 1 | `http.Method*` constants not resolved | Bug | High — breaks `router.Method()` for all Chi users |
| 2 | Chi middleware detection passes `nil` | Bug | High — all Chi endpoints classified as public |
| 3 | No cross-file middleware detection | Architecture | High — affects any app with separate middleware/route files |
| 4 | Chained calls not resolved in AST | Bug | Medium — misses `wrapper.Router().Use()` patterns |
| 5 | `Handle`/`HandleFunc` not recognized | Missing | Medium — valid Chi registration methods skipped |
| 6 | Handler name shows wrapper, not actual function | UX | Low — cosmetic but hurts usability |
| 7 | AP001 and AP008 are duplicates | Rules | Low — noise in findings output |
| 8 | AP002/AP004 overlap consideration | Rules | Low — design consideration, not a bug |
| 9 | No OpenAPI spec integration | Missing | Medium — missed opportunity for accurate classification |
| 10 | No `public_routes` config | Missing | Medium — can't represent runtime auth exclusions |

Items 1-3 are the critical ones — they make the Chi discoverer essentially non-functional for real-world projects. The good news is the code structure is already there (the `Method`/`MethodFunc` handler, the `ChiExtractor.Extract()` method), it just needs to be wired up correctly.

The `feat/chi-improvements` branch in this fork contains working fixes for items 1-4, 9, and 10.
