//! SQLite access layer and the initial dataset of the workshop.
use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;

const DDL: &str = "
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
);";

const SEED_TOOLS: [(&str, &str, &str, f64); 5] = [
    ("Circular saw", "cutting", "190 mm blade, 1400 W", 12.5),
    ("Impact driver", "drilling", "18 V, two batteries", 8.0),
    ("Mitre saw", "cutting", "Sliding, 255 mm", 18.0),
    ("Heat gun", "finishing", "2000 W, variable", 5.5),
    ("Mortar mixer", "masonry", "1600 W, 140 mm paddle", 15.0),
];

const SEED_MEMBERS: [(&str, &str, &str, &str); 3] = [
    ("ada@toolshed.example", "Ada Mallory", "workshop-keeper", "staff"),
    ("jun@toolshed.example", "Jun Watanabe", "sawdust-season", "member"),
    ("pierre@toolshed.example", "Pierre Lefranc", "bench-grinder", "member"),
];

#[derive(Debug, Serialize)]
pub struct Tool {
    pub id: i64,
    pub name: String,
    pub category: String,
    pub description: String,
    pub daily_rate: f64,
    pub available: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Member {
    pub id: i64,
    pub email: String,
    pub full_name: String,
    #[serde(skip)]
    pub password: String,
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct Rental {
    pub id: i64,
    pub member_id: i64,
    pub tool_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    pub taken_on: String,
    pub due_on: String,
    pub notes: String,
    pub returned: bool,
}

/// A connection shared across handlers; SQLite serialises the writes for us.
#[derive(Clone)]
pub struct Store(Arc<Mutex<Connection>>);

impl Store {
    pub fn open(file: &str) -> rusqlite::Result<Self> {
        if let Some(dir) = Path::new(file).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let connection = Connection::open(file)?;
        connection.execute_batch(DDL)?;
        let store = Self(Arc::new(Mutex::new(connection)));
        store.seed()?;
        Ok(store)
    }

    fn seed(&self) -> rusqlite::Result<()> {
        let connection = self.0.lock().expect("store lock");
        let count: i64 = connection.query_row("SELECT COUNT(*) FROM tools", [], |r| r.get(0))?;
        if count > 0 {
            return Ok(());
        }
        for (name, category, description, rate) in SEED_TOOLS {
            connection.execute(
                "INSERT INTO tools (name, category, description, daily_rate) VALUES (?1, ?2, ?3, ?4)",
                params![name, category, description, rate],
            )?;
        }
        for (email, name, password, role) in SEED_MEMBERS {
            let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST).expect("hash the seed password");
            connection.execute(
                "INSERT INTO members (email, full_name, password, role) VALUES (?1, ?2, ?3, ?4)",
                params![email, name, hash, role],
            )?;
        }
        Ok(())
    }

    fn read_tool(row: &Row) -> rusqlite::Result<Tool> {
        Ok(Tool {
            id: row.get("id")?,
            name: row.get("name")?,
            category: row.get("category")?,
            description: row.get("description")?,
            daily_rate: row.get("daily_rate")?,
            available: row.get::<_, i64>("available")? != 0,
        })
    }

    fn read_member(row: &Row) -> rusqlite::Result<Member> {
        Ok(Member {
            id: row.get("id")?,
            email: row.get("email")?,
            full_name: row.get("full_name")?,
            password: row.get("password")?,
            role: row.get("role")?,
        })
    }

    fn read_rental(row: &Row, with_tool_name: bool) -> rusqlite::Result<Rental> {
        Ok(Rental {
            id: row.get("id")?,
            member_id: row.get("member_id")?,
            tool_id: row.get("tool_id")?,
            tool_name: if with_tool_name { row.get("tool_name")? } else { None },
            taken_on: row.get("taken_on")?,
            due_on: row.get("due_on")?,
            notes: row.get("notes")?,
            returned: row.get::<_, i64>("returned")? != 0,
        })
    }

    pub fn tools_ordered_by(&self, column: &str) -> rusqlite::Result<Vec<Tool>> {
        let connection = self.0.lock().expect("store lock");
        let sql = format!("SELECT * FROM tools ORDER BY {column}");
        let mut statement = connection.prepare(&sql)?;
        let rows = statement.query_map([], |r| Self::read_tool(r))?;
        rows.collect()
    }

    pub fn top_tools(&self, limit: i64) -> rusqlite::Result<Vec<Tool>> {
        let connection = self.0.lock().expect("store lock");
        let mut statement = connection.prepare("SELECT * FROM tools ORDER BY name LIMIT ?1")?;
        let rows = statement.query_map([limit], |r| Self::read_tool(r))?;
        rows.collect()
    }

    pub fn search_tools(&self, term: &str) -> rusqlite::Result<Vec<Tool>> {
        let connection = self.0.lock().expect("store lock");
        let like = format!("%{term}%");
        let mut statement =
            connection.prepare("SELECT * FROM tools WHERE name LIKE ?1 OR description LIKE ?1")?;
        let rows = statement.query_map([&like], |r| Self::read_tool(r))?;
        rows.collect()
    }

    pub fn tool(&self, id: i64) -> rusqlite::Result<Option<Tool>> {
        let connection = self.0.lock().expect("store lock");
        connection
            .query_row("SELECT * FROM tools WHERE id = ?1", [id], |r| Self::read_tool(r))
            .optional()
    }

    pub fn member_by_email(&self, email: &str) -> rusqlite::Result<Option<Member>> {
        let connection = self.0.lock().expect("store lock");
        connection
            .query_row("SELECT * FROM members WHERE email = ?1", [email], |r| {
                Self::read_member(r)
            })
            .optional()
    }

    pub fn member(&self, id: i64) -> rusqlite::Result<Option<Member>> {
        let connection = self.0.lock().expect("store lock");
        connection
            .query_row("SELECT * FROM members WHERE id = ?1", [id], |r| Self::read_member(r))
            .optional()
    }

    pub fn rentals_of(&self, member_id: i64) -> rusqlite::Result<Vec<Rental>> {
        let connection = self.0.lock().expect("store lock");
        let mut statement = connection.prepare(
            "SELECT r.*, t.name AS tool_name FROM rentals r
             JOIN tools t ON t.id = r.tool_id
             WHERE r.member_id = ?1 ORDER BY r.taken_on DESC",
        )?;
        let rows = statement.query_map([member_id], |r| Self::read_rental(r, true))?;
        rows.collect()
    }

    pub fn rental_of(&self, rental_id: i64, member_id: i64) -> rusqlite::Result<Option<Rental>> {
        let connection = self.0.lock().expect("store lock");
        connection
            .query_row(
                "SELECT * FROM rentals WHERE id = ?1 AND member_id = ?2",
                params![rental_id, member_id],
                |r| Self::read_rental(r, false),
            )
            .optional()
    }

    pub fn create_rental(&self, member_id: i64, tool_id: i64, taken_on: &str, due_on: &str,
                         notes: &str) -> rusqlite::Result<i64> {
        let connection = self.0.lock().expect("store lock");
        connection.execute(
            "INSERT INTO rentals (member_id, tool_id, taken_on, due_on, notes)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![member_id, tool_id, taken_on, due_on, notes],
        )?;
        Ok(connection.last_insert_rowid())
    }

    pub fn set_tool_available(&self, tool_id: i64, available: bool) -> rusqlite::Result<()> {
        let connection = self.0.lock().expect("store lock");
        connection.execute(
            "UPDATE tools SET available = ?1 WHERE id = ?2",
            params![i64::from(available), tool_id],
        )?;
        Ok(())
    }

    pub fn close_rental(&self, rental_id: i64) -> rusqlite::Result<()> {
        let connection = self.0.lock().expect("store lock");
        connection.execute("UPDATE rentals SET returned = 1 WHERE id = ?1", [rental_id])?;
        Ok(())
    }
}
