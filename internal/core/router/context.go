package router

import (
	"context"
	"net/http"
)

// Middleware represents a middleware function
type Middleware func(http.Handler) http.Handler

// Context keys for route parameters
type contextKey string

const (
	routeParamsKey contextKey = "route_params"
)

// SetRouteParams sets route parameters in the context
func SetRouteParams(ctx context.Context, params map[string]string) context.Context {
	return context.WithValue(ctx, routeParamsKey, params)
}

// GetRouteParams gets route parameters from the context
func GetRouteParams(ctx context.Context) map[string]string {
	if params, ok := ctx.Value(routeParamsKey).(map[string]string); ok {
		return params
	}
	return make(map[string]string)
}

// GetRouteParam gets a specific route parameter from the context
func GetRouteParam(ctx context.Context, key string) string {
	params := GetRouteParams(ctx)
	return params[key]
}

// HasRouteParam checks if a route parameter exists in the context
func HasRouteParam(ctx context.Context, key string) bool {
	params := GetRouteParams(ctx)
	_, exists := params[key]
	return exists
}

// RouteParamMiddleware creates middleware that extracts route parameters
// This is useful when integrating with other routers that don't automatically set context
func RouteParamMiddleware(paramExtractor func(*http.Request) map[string]string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			params := paramExtractor(r)
			ctx := SetRouteParams(r.Context(), params)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}