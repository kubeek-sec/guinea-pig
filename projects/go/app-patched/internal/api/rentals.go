package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"toolshed/internal/store"
)

const defaultDays = 7

func (s *Server) myRentals(w http.ResponseWriter, _ *http.Request, m *store.Member) {
	rows, err := s.DB.Query(
		`SELECT r.id, r.member_id, r.tool_id, t.name, r.taken_on, r.due_on, r.notes, r.returned
		 FROM rentals r JOIN tools t ON t.id = r.tool_id
		 WHERE r.member_id = ? ORDER BY r.taken_on DESC`, m.ID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "cannot read the rentals")
		return
	}
	defer rows.Close()
	rentals := []store.Rental{}
	for rows.Next() {
		var x store.Rental
		if err := rows.Scan(&x.ID, &x.MemberID, &x.ToolID, &x.ToolName,
			&x.TakenOn, &x.DueOn, &x.Notes, &x.Returned); err != nil {
			fail(w, http.StatusInternalServerError, "cannot read the rentals")
			return
		}
		rentals = append(rentals, x)
	}
	writeJSON(w, http.StatusOK, map[string]any{"rentals": rentals})
}

func (s *Server) takeOut(w http.ResponseWriter, r *http.Request, m *store.Member) {
	var body struct {
		ToolID int64  `json:"tool_id"`
		Days   int    `json:"days"`
		Notes  string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "bad request body")
		return
	}
	var available bool
	if err := s.DB.QueryRow("SELECT available FROM tools WHERE id = ?", body.ToolID).
		Scan(&available); err != nil {
		fail(w, http.StatusNotFound, "no such tool")
		return
	}
	if !available {
		fail(w, http.StatusConflict, "already out")
		return
	}
	days := body.Days
	if days <= 0 {
		days = defaultDays
	}
	today := time.Now()
	due := today.AddDate(0, 0, days)
	res, err := s.DB.Exec(
		"INSERT INTO rentals (member_id, tool_id, taken_on, due_on, notes) VALUES (?, ?, ?, ?, ?)",
		m.ID, body.ToolID, today.Format(time.DateOnly), due.Format(time.DateOnly), body.Notes)
	if err != nil {
		fail(w, http.StatusInternalServerError, "cannot record the rental")
		return
	}
	if _, err := s.DB.Exec("UPDATE tools SET available = 0 WHERE id = ?", body.ToolID); err != nil {
		fail(w, http.StatusInternalServerError, "cannot update the tool")
		return
	}
	id, _ := res.LastInsertId()
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "due_on": due.Format(time.DateOnly)})
}

func (s *Server) bringBack(w http.ResponseWriter, r *http.Request, m *store.Member) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad rental id")
		return
	}
	var toolID int64
	err = s.DB.QueryRow("SELECT tool_id FROM rentals WHERE id = ? AND member_id = ?", id, m.ID).
		Scan(&toolID)
	if err != nil {
		fail(w, http.StatusNotFound, "no such rental")
		return
	}
	if _, err := s.DB.Exec("UPDATE rentals SET returned = 1 WHERE id = ?", id); err != nil {
		fail(w, http.StatusInternalServerError, "cannot close the rental")
		return
	}
	if _, err := s.DB.Exec("UPDATE tools SET available = 1 WHERE id = ?", toolID); err != nil {
		fail(w, http.StatusInternalServerError, "cannot update the tool")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "returned"})
}
