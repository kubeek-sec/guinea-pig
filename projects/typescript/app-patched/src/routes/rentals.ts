// Taking tools out and bringing them back.
import { Router } from "express";

import { signedIn } from "../auth";
import type { DB, Rental, Tool } from "../db";

const DEFAULT_DAYS = 7;

function isoDate(d: Date): string {
  return d.toISOString().slice(0, 10);
}

export function rentalRoutes(db: DB): Router {
  const router = Router();

  router.get("/api/rentals", signedIn(db), (req, res) => {
    const rentals = db
      .prepare(
        `SELECT r.*, t.name AS tool_name FROM rentals r
         JOIN tools t ON t.id = r.tool_id
         WHERE r.member_id = ? ORDER BY r.taken_on DESC`,
      )
      .all(req.member!.id) as Rental[];
    res.json({ rentals });
  });

  router.post("/api/rentals", signedIn(db), (req, res) => {
    const body = req.body ?? {};
    const tool = db.prepare("SELECT * FROM tools WHERE id = ?").get(body.tool_id) as Tool | undefined;
    if (!tool) {
      res.status(404).json({ error: "no such tool" });
      return;
    }
    if (!tool.available) {
      res.status(409).json({ error: "already out" });
      return;
    }
    const days = Number(body.days) > 0 ? Number(body.days) : DEFAULT_DAYS;
    const today = new Date();
    const due = new Date(today.getTime() + days * 86400000);
    const info = db
      .prepare(
        "INSERT INTO rentals (member_id, tool_id, taken_on, due_on, notes) VALUES (?, ?, ?, ?, ?)",
      )
      .run(req.member!.id, tool.id, isoDate(today), isoDate(due), String(body.notes ?? ""));
    db.prepare("UPDATE tools SET available = 0 WHERE id = ?").run(tool.id);
    res.status(201).json({ id: info.lastInsertRowid, due_on: isoDate(due) });
  });

  router.post("/api/rentals/:id/return", signedIn(db), (req, res) => {
    const rental = db
      .prepare("SELECT * FROM rentals WHERE id = ? AND member_id = ?")
      .get(req.params.id, req.member!.id) as Rental | undefined;
    if (!rental) {
      res.status(404).json({ error: "no such rental" });
      return;
    }
    db.prepare("UPDATE rentals SET returned = 1 WHERE id = ?").run(rental.id);
    db.prepare("UPDATE tools SET available = 1 WHERE id = ?").run(rental.tool_id);
    res.json({ status: "returned" });
  });

  return router;
}
