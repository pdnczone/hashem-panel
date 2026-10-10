package main

import (
	"net/http"
	"strings"
)

// maxRequestBodyBytes caps JSON/API request bodies on state-changing methods.
const maxRequestBodyBytes = 1 << 20

const panelCSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; " +
	"style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; " +
	"connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"

// isWebSocketUpgrade reports whether the request asks for a protocol upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// securityMiddleware sets hardening headers on every response and caps request
// body size for mutating methods. It never wraps the ResponseWriter so
// WebSocket hijacking and streaming keep working. The panel has no
// upload-style endpoints (updates are downloaded server-side), so every
// mutating request except websocket upgrades is capped.
func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Content-Security-Policy", panelCSP)
		if isRequestHTTPS(r) {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			if !isWebSocketUpgrade(r) && r.Body != nil && r.Body != http.NoBody {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// panelHandler returns the panel mux wrapped with the security middleware.
// Resolved lazily so the HTTPS listener always serves the current mux.
func panelHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metricsMiddleware(securityMiddleware(panelMux)).ServeHTTP(w, r)
	})
}
