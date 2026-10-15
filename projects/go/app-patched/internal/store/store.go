// Package store holds the SQLite access layer and the initial workshop dataset.
package store

import (
	"database/sql"
	"os"
	"path/filepath"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS members (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    email     TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    password  TEXT NOT NULL,
    role      TEXT NOT NULL DEFAULT 'member'
);
CREATE TABLE IF NOT EXISTS tools (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    category    TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    daily_rate  REAL NOT NULL DEFAULT 0,
    available   INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS rentals (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER NOT NULL REFERENCES members(id),
    tool_id   INTEGER NOT NULL REFERENCES tools(id),
    taken_on  TEXT NOT NULL,
    due_on    TEXT NOT NULL,
    notes     TEXT NOT NULL DEFAULT '',
    returned  INTEGER NOT NULL DEFAULT 0
);`

type Tool struct {
	ID          int64   `json:"id"`
	Name        string  `json:"name"`
	Category    string  `json:"category"`
	Description string  `json:"description"`
	DailyRate   float64 `json:"daily_rate"`
	Available   bool    `json:"available"`
}

type Member struct {
	ID       int64  `json:"id"`
	Email    string `json:"email"`
	FullName string `json:"full_name"`
	Password string `json:"-"`
	Role     string `json:"role"`
}

type Rental struct {
	ID       int64  `json:"id"`
	MemberID int64  `json:"member_id"`
	ToolID   int64  `json:"tool_id"`
	ToolName string `json:"tool_name,omitempty"`
	TakenOn  string `json:"taken_on"`
	DueOn    string `json:"due_on"`
	Notes    string `json:"notes"`
	Returned bool   `json:"returned"`
}

var seedTools = []Tool{
	{Name: "Circular saw", Category: "cutting", Description: "190 mm blade, 1400 W", DailyRate: 12.5},
	{Name: "Impact driver", Category: "drilling", Description: "18 V, two batteries", DailyRate: 8.0},
	{Name: "Mitre saw", Category: "cutting", Description: "Sliding, 255 mm", DailyRate: 18.0},
	{Name: "Heat gun", Category: "finishing", Description: "2000 W, variable", DailyRate: 5.5},
	{Name: "Mortar mixer", Category: "masonry", Description: "1600 W, 140 mm paddle", DailyRate: 15.0},
}

var seedMembers = []struct{ Email, Name, Password, Role string }{
	{"ada@toolshed.example", "Ada Mallory", "workshop-keeper", "staff"},
	{"jun@toolshed.example", "Jun Watanabe", "sawdust-season", "member"},
	{"pierre@toolshed.example", "Pierre Lefranc", "bench-grinder", "member"},
}

// Open connects to the SQLite file, creates the schema and seeds it once.
func Open(path string) (*sql.DB, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM tools").Scan(&n); err != nil {
		return nil, err
	}
	if n == 0 {
		if err := seed(db); err != nil {
			return nil, err
		}
	}
	return db, nil
}

func seed(db *sql.DB) error {
	for _, t := range seedTools {
		if _, err := db.Exec(
			"INSERT INTO tools (name, category, description, daily_rate) VALUES (?, ?, ?, ?)",
			t.Name, t.Category, t.Description, t.DailyRate); err != nil {
			return err
		}
	}
	for _, m := range seedMembers {
		hash, err := bcrypt.GenerateFromPassword([]byte(m.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		if _, err := db.Exec(
			"INSERT INTO members (email, full_name, password, role) VALUES (?, ?, ?, ?)",
			m.Email, m.Name, string(hash), m.Role); err != nil {
			return err
		}
	}
	return nil
}
