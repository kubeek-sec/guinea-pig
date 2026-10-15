package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"toolshed/internal/auth"
	"toolshed/internal/store"
)

func (s *Server) signIn(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "bad request body")
		return
	}
	member, err := auth.Authenticate(s.DB, body.Email, body.Password)
	if err != nil {
		fail(w, http.StatusUnauthorized, "bad credentials")
		return
	}
	token, err := auth.Issue(member)
	if err != nil {
		fail(w, http.StatusInternalServerError, "cannot issue a token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token, "role": member.Role})
}

func (s *Server) whoami(w http.ResponseWriter, _ *http.Request, m *store.Member) {
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) getMember(w http.ResponseWriter, r *http.Request, _ *store.Member) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad member id")
		return
	}
	var m store.Member
	err = s.DB.QueryRow(
		"SELECT id, email, full_name, role FROM members WHERE id = ?", id).
		Scan(&m.ID, &m.Email, &m.FullName, &m.Role)
	if err != nil {
		fail(w, http.StatusNotFound, "no such member")
		return
	}
	writeJSON(w, http.StatusOK, m)
}
