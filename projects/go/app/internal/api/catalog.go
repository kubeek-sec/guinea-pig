package api

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"

	"toolshed/internal/store"
)

var sortable = map[string]bool{"name": true, "category": true, "daily_rate": true}

var homePage = template.Must(template.New("home").Parse(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Toolshed</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:48rem}
table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #ddd;padding:.5rem;text-align:left}
.out{color:#999}</style></head>
<body><h1>Toolshed</h1><p>Tools the workshop lends to its members.</p>
<table><tr><th>Tool</th><th>Category</th><th>Per day</th><th>Status</th></tr>
{{range .}}<tr><td>{{.Name}}</td><td>{{.Category}}</td><td>{{printf "%.2f" .DailyRate}} &euro;</td>
<td>{{if .Available}}on the rack{{else}}<span class="out">out</span>{{end}}</td></tr>{{end}}
</table><p><a href="/openapi.yml">API description</a></p></body></html>`))

func (s *Server) scanTools(rows interface {
	Next() bool
	Scan(...any) error
	Close() error
}) ([]store.Tool, error) {
	defer rows.Close()
	tools := []store.Tool{}
	for rows.Next() {
		var t store.Tool
		if err := rows.Scan(&t.ID, &t.Name, &t.Category, &t.Description, &t.DailyRate, &t.Available); err != nil {
			return nil, err
		}
		tools = append(tools, t)
	}
	return tools, nil
}

func (s *Server) home(w http.ResponseWriter, _ *http.Request) {
	rows, err := s.DB.Query("SELECT id, name, category, description, daily_rate, available FROM tools ORDER BY name LIMIT 20")
	if err != nil {
		fail(w, http.StatusInternalServerError, "cannot read the catalogue")
		return
	}
	tools, err := s.scanTools(rows)
	if err != nil {
		fail(w, http.StatusInternalServerError, "cannot read the catalogue")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = homePage.Execute(w, tools)
}

func (s *Server) listTools(w http.ResponseWriter, r *http.Request) {
	sort := r.URL.Query().Get("sort")
	if sort == "" {
		sort = "name"
	}
	if !sortable[sort] {
		fail(w, http.StatusBadRequest, fmt.Sprintf("cannot sort on %q", sort))
		return
	}
	rows, err := s.DB.Query("SELECT id, name, category, description, daily_rate, available FROM tools ORDER BY " + sort)
	if err != nil {
		fail(w, http.StatusInternalServerError, "cannot read the catalogue")
		return
	}
	tools, err := s.scanTools(rows)
	if err != nil {
		fail(w, http.StatusInternalServerError, "cannot read the catalogue")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tools": tools})
}

func (s *Server) searchTools(w http.ResponseWriter, r *http.Request) {
	term := r.URL.Query().Get("q")
	like := "%" + term + "%"
	rows, err := s.DB.Query(
		"SELECT id, name, category, description, daily_rate, available FROM tools WHERE name LIKE ? OR description LIKE ?",
		like, like)
	if err != nil {
		fail(w, http.StatusInternalServerError, "cannot read the catalogue")
		return
	}
	tools, err := s.scanTools(rows)
	if err != nil {
		fail(w, http.StatusInternalServerError, "cannot read the catalogue")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"query": term, "tools": tools})
}

func (s *Server) getTool(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad tool id")
		return
	}
	var t store.Tool
	err = s.DB.QueryRow(
		"SELECT id, name, category, description, daily_rate, available FROM tools WHERE id = ?", id).
		Scan(&t.ID, &t.Name, &t.Category, &t.Description, &t.DailyRate, &t.Available)
	if err != nil {
		fail(w, http.StatusNotFound, "no such tool")
		return
	}
	writeJSON(w, http.StatusOK, t)
}
