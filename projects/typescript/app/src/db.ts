// SQLite access layer and the initial dataset of the workshop.
import fs from "node:fs";
import path from "node:path";

import { DatabaseSync } from "node:sqlite";

import bcrypt from "bcryptjs";

export interface Tool {
  id: number;
  name: string;
  category: string;
  description: string;
  daily_rate: number;
  available: number;
}

export interface Member {
  id: number;
  email: string;
  full_name: string;
  password: string;
  role: string;
}

export interface Rental {
  id: number;
  member_id: number;
  tool_id: number;
  tool_name?: string;
  taken_on: string;
  due_on: string;
  notes: string;
  returned: number;
}

const SCHEMA = `
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
);`;

const SEED_TOOLS: Array<[string, string, string, number]> = [
  ["Circular saw", "cutting", "190 mm blade, 1400 W", 12.5],
  ["Impact driver", "drilling", "18 V, two batteries", 8.0],
  ["Mitre saw", "cutting", "Sliding, 255 mm", 18.0],
  ["Heat gun", "finishing", "2000 W, variable", 5.5],
  ["Mortar mixer", "masonry", "1600 W, 140 mm paddle", 15.0],
];

const SEED_MEMBERS: Array<[string, string, string, string]> = [
  ["ada@toolshed.example", "Ada Mallory", "workshop-keeper", "staff"],
  ["jun@toolshed.example", "Jun Watanabe", "sawdust-season", "member"],
  ["pierre@toolshed.example", "Pierre Lefranc", "bench-grinder", "member"],
];

export type DB = DatabaseSync;

export function open(file: string): DB {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec(SCHEMA);
  const { n } = db.prepare("SELECT COUNT(*) AS n FROM tools").get() as { n: number };
  if (n === 0) {
    const tool = db.prepare(
      "INSERT INTO tools (name, category, description, daily_rate) VALUES (?, ?, ?, ?)");
    for (const row of SEED_TOOLS) tool.run(...row);
    const member = db.prepare(
      "INSERT INTO members (email, full_name, password, role) VALUES (?, ?, ?, ?)");
    for (const [email, name, password, role] of SEED_MEMBERS) {
      member.run(email, name, bcrypt.hashSync(password, 10), role);
    }
  }
  return db;
}
