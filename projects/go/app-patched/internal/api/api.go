// Package api wires the HTTP surface of the workshop.
package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"

	"toolshed/internal/auth"
	"toolshed/internal/store"
)

type Server struct {
	DB      *sql.DB
	Uploads string
	Version string
}

func New(db *sql.DB, uploads, version string) *Server {
	return &Server{DB: db, Uploads: uploads, Version: version}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func fail(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// signedIn rejects the request when no valid bearer token is present.
func (s *Server) signedIn(next func(http.ResponseWriter, *http.Request, *store.Member)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m := auth.FromRequest(s.DB, r)
		if m == nil {
			fail(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), auth.MemberKey, m)), m)
	}
}

// staffOnly additionally requires the staff role.
func (s *Server) staffOnly(next func(http.ResponseWriter, *http.Request, *store.Member)) http.HandlerFunc {
	return s.signedIn(func(w http.ResponseWriter, r *http.Request, m *store.Member) {
		if m.Role != "staff" {
			fail(w, http.StatusForbidden, "staff only")
			return
		}
		next(w, r, m)
	})
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /openapi.yml", s.openapi)
	mux.HandleFunc("GET /{$}", s.home)

	mux.HandleFunc("GET /api/tools", s.listTools)
	mux.HandleFunc("GET /api/tools/search", s.searchTools)
	mux.HandleFunc("GET /api/tools/{id}", s.getTool)

	mux.HandleFunc("POST /api/session", s.signIn)
	mux.HandleFunc("GET /api/members/me", s.signedIn(s.whoami))
	mux.HandleFunc("GET /api/members/{id}", s.staffOnly(s.getMember))

	mux.HandleFunc("GET /api/rentals", s.signedIn(s.myRentals))
	mux.HandleFunc("POST /api/rentals", s.signedIn(s.takeOut))
	mux.HandleFunc("POST /api/rentals/{id}/return", s.signedIn(s.bringBack))

	mux.HandleFunc("POST /api/photos", s.signedIn(s.uploadPhoto))
	mux.HandleFunc("GET /api/photos/{name}", s.fetchPhoto)
	return mux
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.Version})
}

func (s *Server) openapi(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	http.ServeFile(w, r, "openapi.yml")
}
