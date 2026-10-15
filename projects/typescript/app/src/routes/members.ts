// Member accounts and sign-in.
import { Router } from "express";

import { authenticate, issueToken, signedIn, staffOnly } from "../auth";
import type { DB, Member } from "../db";

export function memberRoutes(db: DB): Router {
  const router = Router();

  router.post("/api/session", (req, res) => {
    const { email = "", password = "" } = req.body ?? {};
    const member = authenticate(db, String(email), String(password));
    if (!member) {
      res.status(401).json({ error: "bad credentials" });
      return;
    }
    res.json({ token: issueToken(member), role: member.role });
  });

  router.get("/api/members/me", signedIn(db), (req, res) => {
    const { password, ...member } = req.member as Member;
    void password;
    res.json(member);
  });

  router.get("/api/members/:id", signedIn(db), staffOnly, (req, res) => {
    const row = db
      .prepare("SELECT id, email, full_name, role FROM members WHERE id = ?")
      .get(req.params.id);
    if (!row) {
      res.status(404).json({ error: "no such member" });
      return;
    }
    res.json(row);
  });

  return router;
}
